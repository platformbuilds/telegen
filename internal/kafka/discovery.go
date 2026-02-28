// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// DiscoveryConfig configures automatic Kafka cluster discovery from K8s CRDs
type DiscoveryConfig struct {
	// Enabled enables automatic discovery of Kafka clusters from CRDs
	Enabled bool `yaml:"enabled"`

	// Namespaces to watch for Kafka CRDs (empty = all namespaces)
	Namespaces []string `yaml:"namespaces"`

	// LabelSelector filters which Kafka CRs to discover
	LabelSelector string `yaml:"label_selector"`

	// Strimzi configures Strimzi Kafka operator CRD discovery
	Strimzi StrimziDiscoveryConfig `yaml:"strimzi"`

	// Confluent configures Confluent for Kubernetes CRD discovery
	Confluent ConfluentDiscoveryConfig `yaml:"confluent"`

	// ResyncInterval is how often to re-list all CRs (default: 5m)
	ResyncInterval time.Duration `yaml:"resync_interval"`

	// DefaultConfig provides default values for discovered clusters
	DefaultConfig DiscoveredClusterDefaults `yaml:"default_config"`
}

// StrimziDiscoveryConfig configures Strimzi operator discovery
type StrimziDiscoveryConfig struct {
	// Enabled enables Strimzi Kafka CR discovery
	Enabled bool `yaml:"enabled"`

	// ListenerName is the Strimzi listener name to use for broker addresses
	// Default: "plain" for non-TLS, "tls" for TLS
	ListenerName string `yaml:"listener_name"`

	// UseInternalListener uses internal (cluster-local) addresses
	// Default: true (telegen runs in-cluster)
	UseInternalListener bool `yaml:"use_internal_listener"`
}

// ConfluentDiscoveryConfig configures Confluent for Kubernetes discovery
type ConfluentDiscoveryConfig struct {
	// Enabled enables Confluent Kafka CR discovery
	Enabled bool `yaml:"enabled"`

	// UseInternalEndpoint uses internal (cluster-local) endpoint
	// Default: true (telegen runs in-cluster)
	UseInternalEndpoint bool `yaml:"use_internal_endpoint"`
}

// DiscoveredClusterDefaults provides default config for discovered clusters
type DiscoveredClusterDefaults struct {
	// GroupIDPrefix is prepended to cluster name for group_id
	// e.g., "telegen-" + cluster_name -> "telegen-my-kafka"
	GroupIDPrefix string `yaml:"group_id_prefix"`

	// Topics to consume from (applied to all discovered clusters)
	Topics []string `yaml:"topics"`

	// InitialOffset for discovered clusters
	InitialOffset string `yaml:"initial_offset"`

	// UseLeaderEpoch default for discovered clusters
	UseLeaderEpoch bool `yaml:"use_leader_epoch"`

	// SessionTimeout default
	SessionTimeout time.Duration `yaml:"session_timeout"`

	// HeaderExtraction defaults
	HeaderExtraction HeaderExtractionConfig `yaml:"header_extraction"`

	// Telemetry defaults
	Telemetry TelemetryConfig `yaml:"telemetry"`
}

// DiscoveredCluster represents a Kafka cluster discovered from a K8s CRD
type DiscoveredCluster struct {
	// Name is the unique identifier (namespace/name)
	Name string

	// Namespace where the Kafka CR is deployed
	Namespace string

	// CRDKind indicates the source: "strimzi" or "confluent"
	CRDKind string

	// Brokers is the list of broker addresses
	Brokers []string

	// TLSEnabled indicates if the cluster requires TLS
	TLSEnabled bool

	// AuthType indicates authentication type if any (e.g., "scram-sha-512")
	AuthType string

	// SecretRef points to the K8s Secret for credentials (if auth enabled)
	SecretRef *SecretReference

	// TLSSecretRef points to the K8s Secret for TLS certs
	TLSSecretRef *SecretReference

	// Labels from the original Kafka CR
	Labels map[string]string

	// Annotations from the original Kafka CR
	Annotations map[string]string
}

// SecretReference points to a K8s Secret
type SecretReference struct {
	Namespace string
	Name      string
	Key       string // Key within the secret for the value
}

// DiscoveryEventType represents the type of discovery event
type DiscoveryEventType string

const (
	DiscoveryEventAdded    DiscoveryEventType = "added"
	DiscoveryEventModified DiscoveryEventType = "modified"
	DiscoveryEventDeleted  DiscoveryEventType = "deleted"
)

// DiscoveryEvent is emitted when a Kafka cluster is discovered or removed
type DiscoveryEvent struct {
	Type    DiscoveryEventType
	Cluster DiscoveredCluster
}

// DiscoveryHandler is called when clusters are discovered/removed
type DiscoveryHandler func(event DiscoveryEvent)

// KafkaDiscovery watches for Kafka CRDs and discovers clusters
type KafkaDiscovery struct {
	config        DiscoveryConfig
	logger        *slog.Logger
	dynamicClient dynamic.Interface

	mu              sync.RWMutex
	clusters        map[string]*DiscoveredCluster // key: namespace/name
	handler         DiscoveryHandler
	stopCh          chan struct{}
	wg              sync.WaitGroup
	started         bool
}

// Strimzi CRD GVR - supports both v1 (current) and v1beta2 (legacy)
// The watcher will try v1 first and fall back to v1beta2
var strimziKafkaGVRv1 = schema.GroupVersionResource{
	Group:    "kafka.strimzi.io",
	Version:  "v1",
	Resource: "kafkas",
}

var strimziKafkaGVRv1beta2 = schema.GroupVersionResource{
	Group:    "kafka.strimzi.io",
	Version:  "v1beta2",
	Resource: "kafkas",
}

// Confluent CRD GVR
var confluentKafkaGVR = schema.GroupVersionResource{
	Group:    "platform.confluent.io",
	Version:  "v1beta1",
	Resource: "kafkas",
}

// NewKafkaDiscovery creates a new Kafka cluster discovery watcher
func NewKafkaDiscovery(config DiscoveryConfig, logger *slog.Logger) (*KafkaDiscovery, error) {
	if !config.Enabled {
		return nil, nil
	}

	// Get in-cluster config
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w (discovery requires in-cluster deployment)", err)
	}

	// Create dynamic client for CRD watching
	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	// Set defaults
	if config.ResyncInterval == 0 {
		config.ResyncInterval = 5 * time.Minute
	}
	if config.Strimzi.ListenerName == "" {
		config.Strimzi.ListenerName = "plain"
	}
	if config.DefaultConfig.GroupIDPrefix == "" {
		config.DefaultConfig.GroupIDPrefix = "telegen-"
	}
	if config.DefaultConfig.InitialOffset == "" {
		config.DefaultConfig.InitialOffset = "latest"
	}
	if config.DefaultConfig.SessionTimeout == 0 {
		config.DefaultConfig.SessionTimeout = 30 * time.Second
	}

	return &KafkaDiscovery{
		config:        config,
		logger:        logger,
		dynamicClient: dynamicClient,
		clusters:      make(map[string]*DiscoveredCluster),
		stopCh:        make(chan struct{}),
	}, nil
}

// SetHandler sets the callback for discovery events
func (d *KafkaDiscovery) SetHandler(handler DiscoveryHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handler = handler
}

// Start begins watching for Kafka CRDs
func (d *KafkaDiscovery) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return fmt.Errorf("discovery already started")
	}
	d.started = true
	d.mu.Unlock()

	d.logger.Info("starting kafka cluster discovery",
		slog.Bool("strimzi_enabled", d.config.Strimzi.Enabled),
		slog.Bool("confluent_enabled", d.config.Confluent.Enabled),
		slog.Any("namespaces", d.config.Namespaces),
	)

	// Start Strimzi watcher - tries v1 API first, falls back to v1beta2
	if d.config.Strimzi.Enabled {
		d.wg.Add(1)
		go d.watchStrimziCRD(ctx)
	}

	// Start Confluent watcher
	if d.config.Confluent.Enabled {
		d.wg.Add(1)
		go d.watchCRD(ctx, confluentKafkaGVR, "confluent")
	}

	return nil
}

// Stop stops watching for Kafka CRDs
func (d *KafkaDiscovery) Stop() {
	d.mu.Lock()
	if !d.started {
		d.mu.Unlock()
		return
	}
	close(d.stopCh)
	d.mu.Unlock()

	d.wg.Wait()
	d.logger.Info("kafka discovery stopped")
}

// GetClusters returns all currently discovered clusters
func (d *KafkaDiscovery) GetClusters() []*DiscoveredCluster {
	d.mu.RLock()
	defer d.mu.RUnlock()

	clusters := make([]*DiscoveredCluster, 0, len(d.clusters))
	for _, c := range d.clusters {
		clusters = append(clusters, c)
	}
	return clusters
}

// watchStrimziCRD watches for Strimzi Kafka CRDs, trying v1 API first then falling back to v1beta2
func (d *KafkaDiscovery) watchStrimziCRD(ctx context.Context) {
	defer d.wg.Done()

	// Try v1 API first (current Strimzi version)
	gvr := strimziKafkaGVRv1
	apiVersion := "v1"

	for {
		select {
		case <-d.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		err := d.runWatch(ctx, gvr, "strimzi")
		if err != nil {
			// If v1 fails with not found type error, try v1beta2
			if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "the server could not find") {
				if gvr == strimziKafkaGVRv1 {
					d.logger.Info("strimzi v1 API not available, falling back to v1beta2")
					gvr = strimziKafkaGVRv1beta2
					apiVersion = "v1beta2"
					continue
				}
			}

			d.logger.Error("strimzi watch error, will retry",
				slog.String("api_version", apiVersion),
				slog.Any("error", err),
			)
			select {
			case <-d.stopCh:
				return
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}
	}
}

// watchCRD watches a specific CRD type for Kafka resources
func (d *KafkaDiscovery) watchCRD(ctx context.Context, gvr schema.GroupVersionResource, crdKind string) {
	defer d.wg.Done()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		if err := d.runWatch(ctx, gvr, crdKind); err != nil {
			d.logger.Error("watch error, will retry",
				slog.String("crd_kind", crdKind),
				slog.Any("error", err),
			)
			select {
			case <-d.stopCh:
				return
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}
	}
}

func (d *KafkaDiscovery) runWatch(ctx context.Context, gvr schema.GroupVersionResource, crdKind string) error {
	listOpts := metav1.ListOptions{
		LabelSelector: d.config.LabelSelector,
	}

	// Determine which namespaces to watch
	namespaces := d.config.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{""} // Empty string = all namespaces
	}

	for _, ns := range namespaces {
		var resourceClient dynamic.ResourceInterface
		if ns == "" {
			resourceClient = d.dynamicClient.Resource(gvr)
		} else {
			resourceClient = d.dynamicClient.Resource(gvr).Namespace(ns)
		}

		// Initial list to populate current state
		list, err := resourceClient.List(ctx, listOpts)
		if err != nil {
			d.logger.Warn("failed to list CRD resources",
				slog.String("crd_kind", crdKind),
				slog.String("namespace", ns),
				slog.Any("error", err),
			)
			continue
		}

		// Process initial list
		for _, item := range list.Items {
			d.handleCRDEvent(watch.Added, &item, crdKind)
		}

		// Start watch from current resourceVersion
		listOpts.ResourceVersion = list.GetResourceVersion()
		watcher, err := resourceClient.Watch(ctx, listOpts)
		if err != nil {
			d.logger.Warn("failed to start watch",
				slog.String("crd_kind", crdKind),
				slog.String("namespace", ns),
				slog.Any("error", err),
			)
			continue
		}

		d.logger.Info("watching for kafka CRDs",
			slog.String("crd_kind", crdKind),
			slog.String("namespace", ns),
		)

		// Process watch events
		for {
			select {
			case <-d.stopCh:
				watcher.Stop()
				return nil
			case <-ctx.Done():
				watcher.Stop()
				return ctx.Err()
			case event, ok := <-watcher.ResultChan():
				if !ok {
					// Watch channel closed, need to restart
					return fmt.Errorf("watch channel closed")
				}
				if event.Type == watch.Error {
					return fmt.Errorf("watch error event received")
				}
				if obj, ok := event.Object.(*unstructured.Unstructured); ok {
					d.handleCRDEvent(event.Type, obj, crdKind)
				}
			}
		}
	}

	return nil
}

func (d *KafkaDiscovery) handleCRDEvent(eventType watch.EventType, obj *unstructured.Unstructured, crdKind string) {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	key := fmt.Sprintf("%s/%s", namespace, name)

	d.logger.Debug("received CRD event",
		slog.String("type", string(eventType)),
		slog.String("crd_kind", crdKind),
		slog.String("name", key),
	)

	switch eventType {
	case watch.Added, watch.Modified:
		cluster, err := d.parseKafkaCRD(obj, crdKind)
		if err != nil {
			d.logger.Warn("failed to parse Kafka CRD",
				slog.String("name", key),
				slog.String("crd_kind", crdKind),
				slog.Any("error", err),
			)
			return
		}

		d.mu.Lock()
		existing := d.clusters[key]
		d.clusters[key] = cluster
		handler := d.handler
		d.mu.Unlock()

		if handler != nil {
			evtType := DiscoveryEventAdded
			if existing != nil {
				evtType = DiscoveryEventModified
			}
			handler(DiscoveryEvent{Type: evtType, Cluster: *cluster})
		}

		d.logger.Info("kafka cluster discovered",
			slog.String("name", key),
			slog.String("crd_kind", crdKind),
			slog.Any("brokers", cluster.Brokers),
			slog.Bool("tls_enabled", cluster.TLSEnabled),
		)

	case watch.Deleted:
		d.mu.Lock()
		cluster, exists := d.clusters[key]
		delete(d.clusters, key)
		handler := d.handler
		d.mu.Unlock()

		if exists && handler != nil {
			handler(DiscoveryEvent{Type: DiscoveryEventDeleted, Cluster: *cluster})
		}

		d.logger.Info("kafka cluster removed",
			slog.String("name", key),
			slog.String("crd_kind", crdKind),
		)
	}
}

func (d *KafkaDiscovery) parseKafkaCRD(obj *unstructured.Unstructured, crdKind string) (*DiscoveredCluster, error) {
	switch crdKind {
	case "strimzi":
		return d.parseStrimziKafka(obj)
	case "confluent":
		return d.parseConfluentKafka(obj)
	default:
		return nil, fmt.Errorf("unknown CRD kind: %s", crdKind)
	}
}

// parseStrimziKafka extracts cluster info from a Strimzi Kafka CR
// Supports both kafka.strimzi.io/v1 and kafka.strimzi.io/v1beta2 API versions
// Reference: https://strimzi.io/docs/operators/latest/configuring.html
func (d *KafkaDiscovery) parseStrimziKafka(obj *unstructured.Unstructured) (*DiscoveredCluster, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()

	cluster := &DiscoveredCluster{
		Name:        fmt.Sprintf("%s/%s", namespace, name),
		Namespace:   namespace,
		CRDKind:     "strimzi",
		Labels:      obj.GetLabels(),
		Annotations: obj.GetAnnotations(),
	}

	// Get status.listeners from Strimzi Kafka CR
	// Structure: status.listeners[].name, status.listeners[].bootstrapServers, status.listeners[].addresses[]
	status, found, err := unstructured.NestedMap(obj.Object, "status")
	if err != nil || !found {
		return nil, fmt.Errorf("status not found in Strimzi Kafka CR (cluster may not be ready)")
	}

	listeners, found, err := unstructured.NestedSlice(status, "listeners")
	if err != nil || !found {
		return nil, fmt.Errorf("status.listeners not found (cluster may not be ready)")
	}

	// Find the desired listener by name
	// Common listener names: "plain" (port 9092), "tls" (port 9093), "external"
	targetListener := d.config.Strimzi.ListenerName
	if d.config.Strimzi.UseInternalListener && targetListener == "" {
		// Auto-detect: prefer internal listeners (type: internal)
		// Check for common internal listener names
		for _, preferred := range []string{"plain", "tls", "internal"} {
			if d.findStrimziListener(listeners, preferred) != nil {
				targetListener = preferred
				break
			}
		}
	}
	if targetListener == "" {
		targetListener = "plain" // default fallback
	}

	listenerStatus := d.findStrimziListener(listeners, targetListener)
	if listenerStatus == nil {
		// Try to use any available listener
		if len(listeners) > 0 {
			if first, ok := listeners[0].(map[string]interface{}); ok {
				targetListener, _, _ = unstructured.NestedString(first, "name")
				listenerStatus = first
			}
		}
		if listenerStatus == nil {
			return nil, fmt.Errorf("no listeners found in status")
		}
	}

	// Prefer bootstrapServers field (available in newer Strimzi versions)
	// Format: "host1:port,host2:port,host3:port"
	bootstrapServers, found, _ := unstructured.NestedString(listenerStatus, "bootstrapServers")
	if found && bootstrapServers != "" {
		// Split comma-separated list
		for _, server := range strings.Split(bootstrapServers, ",") {
			server = strings.TrimSpace(server)
			if server != "" {
				cluster.Brokers = append(cluster.Brokers, server)
			}
		}
	}

	// Fallback to addresses[] if bootstrapServers not available
	if len(cluster.Brokers) == 0 {
		addresses, _, _ := unstructured.NestedSlice(listenerStatus, "addresses")
		for _, addr := range addresses {
			addrMap, ok := addr.(map[string]interface{})
			if !ok {
				continue
			}
			host, _, _ := unstructured.NestedString(addrMap, "host")
			port, _, _ := unstructured.NestedInt64(addrMap, "port")
			if host != "" && port > 0 {
				cluster.Brokers = append(cluster.Brokers, fmt.Sprintf("%s:%d", host, port))
			}
		}
	}

	if len(cluster.Brokers) == 0 {
		return nil, fmt.Errorf("no broker addresses found for listener %q", targetListener)
	}

	// Determine TLS from listener spec
	// Check spec.kafka.listeners[].tls field
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	kafkaSpec, _, _ := unstructured.NestedMap(spec, "kafka")
	specListeners, _, _ := unstructured.NestedSlice(kafkaSpec, "listeners")

	for _, l := range specListeners {
		lMap, ok := l.(map[string]interface{})
		if !ok {
			continue
		}
		lName, _, _ := unstructured.NestedString(lMap, "name")
		if lName == targetListener {
			// Check TLS: spec.kafka.listeners[].tls (boolean)
			tlsEnabled, found, _ := unstructured.NestedBool(lMap, "tls")
			if found {
				cluster.TLSEnabled = tlsEnabled
			}
			// Also check listener type: "internal" vs "route", "loadbalancer", "nodeport", "ingress"
			lType, _, _ := unstructured.NestedString(lMap, "type")
			// External listeners are typically TLS
			if lType == "route" || lType == "loadbalancer" || lType == "nodeport" || lType == "ingress" {
				// External listener - might need external access config
				// TLS is usually required for external access
			}

			// Check authentication: spec.kafka.listeners[].authentication.type
			auth, found, _ := unstructured.NestedMap(lMap, "authentication")
			if found {
				authType, _, _ := unstructured.NestedString(auth, "type")
				// Strimzi auth types: tls, scram-sha-512, oauth, custom
				cluster.AuthType = authType
			}
			break
		}
	}

	// Fallback TLS detection from listener name
	if !cluster.TLSEnabled && strings.Contains(targetListener, "tls") {
		cluster.TLSEnabled = true
	}

	// Store certificates from status if available (for client verification)
	certs, _, _ := unstructured.NestedStringSlice(listenerStatus, "certificates")
	if len(certs) > 0 {
		// Certs are available in status for TLS listeners
		// These can be used for CA verification
		cluster.Annotations["strimzi.io/ca-cert-count"] = fmt.Sprintf("%d", len(certs))
	}

	return cluster, nil
}

// findStrimziListener finds a listener by name in the status.listeners slice
func (d *KafkaDiscovery) findStrimziListener(listeners []interface{}, name string) map[string]interface{} {
	for _, l := range listeners {
		lMap, ok := l.(map[string]interface{})
		if !ok {
			continue
		}
		// Check "name" field (primary)
		lName, _, _ := unstructured.NestedString(lMap, "name")
		if lName == name {
			return lMap
		}
		// Also check deprecated "type" field (v1beta2 backward compatibility)
		lType, _, _ := unstructured.NestedString(lMap, "type")
		if lType == name {
			return lMap
		}
	}
	return nil
}

// parseConfluentKafka extracts cluster info from a Confluent Kafka CR
// Based on platform.confluent.io/v1beta1 CRD structure from CFK (Confluent for Kubernetes)
// Reference: https://docs.confluent.io/operator/current/co-api.html
func (d *KafkaDiscovery) parseConfluentKafka(obj *unstructured.Unstructured) (*DiscoveredCluster, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()

	cluster := &DiscoveredCluster{
		Name:        fmt.Sprintf("%s/%s", namespace, name),
		Namespace:   namespace,
		CRDKind:     "confluent",
		Labels:      obj.GetLabels(),
		Annotations: obj.GetAnnotations(),
	}

	// Try to get bootstrap endpoint from status first
	// Status structure: status.listeners[].bootstrapEndpoint, status.listeners[].type
	status, statusFound, _ := unstructured.NestedMap(obj.Object, "status")
	if statusFound {
		// Check for internalSecrets or kafkaClusterID to confirm it's ready
		_, clusterIDFound, _ := unstructured.NestedString(status, "kafkaClusterID")
		if clusterIDFound {
			// Try to get listeners from status
			statusListeners, _, _ := unstructured.NestedSlice(status, "listeners")
			for _, l := range statusListeners {
				lMap, ok := l.(map[string]interface{})
				if !ok {
					continue
				}
				lType, _, _ := unstructured.NestedString(lMap, "type")
				bootstrap, _, _ := unstructured.NestedString(lMap, "bootstrapEndpoint")
				
				// Prefer internal listener for in-cluster
				if d.config.Confluent.UseInternalEndpoint && lType == "internal" && bootstrap != "" {
					cluster.Brokers = append(cluster.Brokers, bootstrap)
				} else if !d.config.Confluent.UseInternalEndpoint && lType == "external" && bootstrap != "" {
					cluster.Brokers = append(cluster.Brokers, bootstrap)
				}
			}
		}
	}

	// If no brokers from status, construct from service naming convention
	// CFK internal service: <name>.<namespace>.svc.cluster.local:9071 (internal listener)
	// CFK replication listener: port 9072
	// CFK external: varies based on externalAccess config
	if len(cluster.Brokers) == 0 {
		if d.config.Confluent.UseInternalEndpoint {
			// Internal listener on port 9071
			cluster.Brokers = []string{fmt.Sprintf("%s.%s.svc.cluster.local:9071", name, namespace)}
		} else {
			// External would need to be parsed from spec.listeners.external.externalAccess
			// Fallback to internal
			cluster.Brokers = []string{fmt.Sprintf("%s.%s.svc.cluster.local:9071", name, namespace)}
		}
	}

	// Parse spec for TLS and authentication configuration
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	
	// Check global TLS config: spec.tls.secretRef
	tls, found, _ := unstructured.NestedMap(spec, "tls")
	if found {
		secretRef, _, _ := unstructured.NestedString(tls, "secretRef")
		if secretRef != "" {
			cluster.TLSEnabled = true
			cluster.TLSSecretRef = &SecretReference{
				Namespace: namespace,
				Name:      secretRef,
			}
		}
	}

	// Check listener-level TLS: spec.listeners.internal.tls.enabled
	listeners, _, _ := unstructured.NestedMap(spec, "listeners")
	if d.config.Confluent.UseInternalEndpoint {
		internal, _, _ := unstructured.NestedMap(listeners, "internal")
		if internal != nil {
			internalTLS, _, _ := unstructured.NestedMap(internal, "tls")
			if internalTLS != nil {
				enabled, _, _ := unstructured.NestedBool(internalTLS, "enabled")
				if enabled {
					cluster.TLSEnabled = true
				}
			}
			// Check authentication: spec.listeners.internal.authentication.type
			auth, _, _ := unstructured.NestedMap(internal, "authentication")
			if auth != nil {
				authType, _, _ := unstructured.NestedString(auth, "type")
				cluster.AuthType = authType // plain, mtls, ldap, oauth, etc.
				// JAAS config secret: spec.listeners.internal.authentication.jaasConfig.secretRef
				jaas, _, _ := unstructured.NestedMap(auth, "jaasConfig")
				if jaas != nil {
					secretRef, _, _ := unstructured.NestedString(jaas, "secretRef")
					if secretRef != "" {
						cluster.SecretRef = &SecretReference{
							Namespace: namespace,
							Name:      secretRef,
						}
					}
				}
			}
		}
	} else {
		external, _, _ := unstructured.NestedMap(listeners, "external")
		if external != nil {
			extTLS, _, _ := unstructured.NestedMap(external, "tls")
			if extTLS != nil {
				enabled, _, _ := unstructured.NestedBool(extTLS, "enabled")
				if enabled {
					cluster.TLSEnabled = true
				}
			}
			auth, _, _ := unstructured.NestedMap(external, "authentication")
			if auth != nil {
				authType, _, _ := unstructured.NestedString(auth, "type")
				cluster.AuthType = authType
				jaas, _, _ := unstructured.NestedMap(auth, "jaasConfig")
				if jaas != nil {
					secretRef, _, _ := unstructured.NestedString(jaas, "secretRef")
					if secretRef != "" {
						cluster.SecretRef = &SecretReference{
							Namespace: namespace,
							Name:      secretRef,
						}
					}
				}
			}
		}
	}

	return cluster, nil
}

// ToClusterConfig converts a discovered cluster to a ClusterConfig for the receiver
func (d *KafkaDiscovery) ToClusterConfig(cluster *DiscoveredCluster) ClusterConfig {
	cfg := Config{
		Enabled:         true,
		Brokers:         cluster.Brokers,
		GroupID:         d.config.DefaultConfig.GroupIDPrefix + strings.ReplaceAll(cluster.Name, "/", "-"),
		ClientID:        "telegen-" + strings.ReplaceAll(cluster.Name, "/", "-"),
		Topics:          d.config.DefaultConfig.Topics,
		InitialOffset:   d.config.DefaultConfig.InitialOffset,
		UseLeaderEpoch:  d.config.DefaultConfig.UseLeaderEpoch,
		SessionTimeout:  d.config.DefaultConfig.SessionTimeout,
		HeaderExtraction: d.config.DefaultConfig.HeaderExtraction,
		Telemetry:       d.config.DefaultConfig.Telemetry,
		MessageMarking: MessageMarking{
			After:            true,
			OnPermanentError: true,
		},
		GroupRebalanceStrategy: "cooperative-sticky",
		HeartbeatInterval:      3 * time.Second,
		RebalanceTimeout:       30 * time.Second,
		Batch: BatchConfig{
			Size:              100,
			Timeout:           5 * time.Second,
			MaxPartitionBytes: 1024 * 1024,
		},
	}

	// Enable TLS if the cluster requires it
	if cluster.TLSEnabled {
		cfg.TLS.Enable = true
		// Note: Actual TLS certs would need to be mounted from secrets
		// This is handled by the deployment/Helm chart
	}

	// TODO: Handle authentication when SecretRef is available
	// This would require accessing K8s secrets for credentials

	return ClusterConfig{
		Name:   cluster.Name,
		Config: cfg,
	}
}

// DefaultDiscoveryConfig returns sensible defaults for discovery configuration
func DefaultDiscoveryConfig() DiscoveryConfig {
	return DiscoveryConfig{
		Enabled:        false,
		Namespaces:     []string{}, // All namespaces
		ResyncInterval: 5 * time.Minute,
		Strimzi: StrimziDiscoveryConfig{
			Enabled:             false,
			ListenerName:        "plain",
			UseInternalListener: true,
		},
		Confluent: ConfluentDiscoveryConfig{
			Enabled:             false,
			UseInternalEndpoint: true,
		},
		DefaultConfig: DiscoveredClusterDefaults{
			GroupIDPrefix:  "telegen-",
			Topics:         []string{},
			InitialOffset:  "latest",
			UseLeaderEpoch: true,
			SessionTimeout: 30 * time.Second,
			Telemetry: TelemetryConfig{
				KafkaReceiverRecords:      true,
				KafkaReceiverOffsetLag:    true,
				KafkaBrokerConnects:       true,
				KafkaBrokerDisconnects:    true,
				KafkaBrokerReadLatency:    true,
				KafkaFetchBatchMetrics:    true,
			},
		},
	}
}
