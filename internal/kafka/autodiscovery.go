// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// AutoDiscoveryConfig is the simplified configuration for automatic Kafka discovery.
// Just specify namespace and topics - everything else is auto-detected.
type AutoDiscoveryConfig struct {
	// Enabled enables automatic Kafka cluster discovery
	Enabled bool `yaml:"enabled"`

	// Namespace to scan for Kafka deployments (required)
	// Can use wildcards: "kafka-*" or "*" for all namespaces
	Namespace string `yaml:"namespace"`

	// Topics to subscribe to (required)
	Topics []string `yaml:"topics"`

	// GroupID for the consumer group (optional, auto-generated if empty)
	GroupID string `yaml:"group_id"`

	// InitialOffset: "latest" or "earliest" (default: "latest")
	InitialOffset string `yaml:"initial_offset"`
}

// AutoDiscovery provides fully automatic Kafka cluster discovery and configuration.
// It detects Strimzi or Confluent deployments, extracts connection details,
// fetches credentials from secrets, and configures receivers automatically.
type AutoDiscovery struct {
	config        AutoDiscoveryConfig
	logger        *slog.Logger
	dynamicClient dynamic.Interface
	clientset     kubernetes.Interface
	restConfig    *rest.Config

	mu             sync.RWMutex
	clusters       map[string]*AutoDiscoveredCluster
	handler        func(event AutoDiscoveryEvent)
	stopCh         chan struct{}
	wg             sync.WaitGroup
	started        bool
}

// AutoDiscoveredCluster contains all the information needed to connect to a discovered Kafka cluster
type AutoDiscoveredCluster struct {
	// Identification
	Name      string
	Namespace string
	Type      string // "strimzi" or "confluent"

	// Connection
	Brokers    []string
	TLSEnabled bool

	// Authentication
	AuthType string // "", "plain", "scram-sha-512", "tls", "oauth"
	Username string
	Password string

	// TLS Certificates (base64 decoded)
	CACert     string
	ClientCert string
	ClientKey  string

	// Source references
	KafkaCRName   string
	SecretName    string
	TLSSecretName string

	// Ready indicates all required credentials were fetched
	Ready bool
	Error string
}

// AutoDiscoveryEvent represents a discovery lifecycle event
type AutoDiscoveryEvent struct {
	Type    string // "discovered", "ready", "updated", "removed", "error"
	Cluster *AutoDiscoveredCluster
	Message string
}

// NewAutoDiscovery creates a new automatic Kafka discovery system.
// This is the "easy mode" - just give it a namespace and topics.
func NewAutoDiscovery(config AutoDiscoveryConfig, logger *slog.Logger) (*AutoDiscovery, error) {
	if !config.Enabled {
		return nil, nil
	}

	// Component-scoped logger for all auto-discovery logs
	logger = logger.With(slog.String("component", "kafka.autodiscovery"))

	logger.Info("kafka auto-discovery initializing",
		slog.String("phase", "init"),
		slog.String("namespace", config.Namespace),
		slog.Any("topics", config.Topics),
	)

	// Get in-cluster config
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		logger.Error("failed to get in-cluster config",
			slog.String("phase", "init"),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("auto-discovery requires in-cluster deployment: %w", err)
	}
	logger.Debug("in-cluster configuration loaded", slog.String("phase", "init"))

	// Create dynamic client for CRD watching
	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		logger.Error("failed to create dynamic client",
			slog.String("phase", "init"),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}
	logger.Debug("dynamic client created", slog.String("phase", "init"))

	// Create clientset for Secret access
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		logger.Error("failed to create kubernetes client",
			slog.String("phase", "init"),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	logger.Debug("kubernetes client created", slog.String("phase", "init"))

	// Set defaults
	if config.InitialOffset == "" {
		config.InitialOffset = "latest"
	}

	logger.Info("kafka auto-discovery ready",
		slog.String("phase", "init"),
		slog.String("namespace", config.Namespace),
		slog.Any("topics", config.Topics),
		slog.String("initial_offset", config.InitialOffset),
	)

	return &AutoDiscovery{
		config:        config,
		logger:        logger,
		dynamicClient: dynamicClient,
		clientset:     clientset,
		restConfig:    restConfig,
		clusters:      make(map[string]*AutoDiscoveredCluster),
		stopCh:        make(chan struct{}),
	}, nil
}

// SetHandler sets the callback for discovery events
func (a *AutoDiscovery) SetHandler(handler func(event AutoDiscoveryEvent)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handler = handler
}

// Start begins the auto-discovery process
func (a *AutoDiscovery) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return fmt.Errorf("auto-discovery already started")
	}
	a.started = true
	a.mu.Unlock()

	a.logger.Info("scanning for kafka deployments",
		slog.String("phase", "scan"),
		slog.String("namespace", a.config.Namespace),
	)

	// Detect which operator is installed
	a.wg.Add(1)
	go a.runDiscovery(ctx)

	return nil
}

// Stop stops the auto-discovery process
func (a *AutoDiscovery) Stop() {
	a.mu.Lock()
	if !a.started {
		a.mu.Unlock()
		return
	}
	close(a.stopCh)
	a.mu.Unlock()

	a.wg.Wait()
	a.logger.Info("kafka auto-discovery stopped", slog.String("phase", "shutdown"))
}

// GetClusters returns all discovered and ready clusters
func (a *AutoDiscovery) GetClusters() []*AutoDiscoveredCluster {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var ready []*AutoDiscoveredCluster
	for _, c := range a.clusters {
		if c.Ready {
			ready = append(ready, c)
		}
	}
	return ready
}

// GetClusterConfigs returns ClusterConfig for all ready clusters
func (a *AutoDiscovery) GetClusterConfigs() []ClusterConfig {
	clusters := a.GetClusters()
	configs := make([]ClusterConfig, 0, len(clusters))

	for _, c := range clusters {
		cfg := a.toClusterConfig(c)
		configs = append(configs, cfg)
	}
	return configs
}

func (a *AutoDiscovery) runDiscovery(ctx context.Context) {
	defer a.wg.Done()

	// Determine namespaces to scan
	namespaces, err := a.resolveNamespaces(ctx)
	if err != nil {
		a.logger.Error("failed to resolve namespaces",
			slog.String("phase", "scan"),
			slog.Any("error", err),
		)
		return
	}

	a.logger.Info("resolved namespaces to scan",
		slog.String("phase", "scan"),
		slog.Int("count", len(namespaces)),
		slog.Any("namespaces", namespaces),
	)

	// Try to detect Kafka deployments
	for _, ns := range namespaces {
		a.scanNamespace(ctx, ns)
	}

	// Continue watching for changes
	a.watchLoop(ctx, namespaces)
}

func (a *AutoDiscovery) resolveNamespaces(ctx context.Context) ([]string, error) {
	ns := a.config.Namespace

	// Exact namespace
	if ns != "" && !strings.Contains(ns, "*") {
		return []string{ns}, nil
	}

	// Wildcard - list all namespaces
	nsList, err := a.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var result []string
	pattern := strings.ReplaceAll(ns, "*", "")

	for _, n := range nsList.Items {
		if ns == "*" || ns == "" {
			result = append(result, n.Name)
		} else if strings.HasPrefix(n.Name, pattern) || strings.HasSuffix(n.Name, pattern) {
			result = append(result, n.Name)
		}
	}

	return result, nil
}

func (a *AutoDiscovery) scanNamespace(ctx context.Context, namespace string) {
	a.logger.Info("scanning namespace for kafka CRDs",
		slog.String("phase", "scan"),
		slog.String("namespace", namespace),
	)

	// Try Strimzi first
	found := a.scanForStrimzi(ctx, namespace)

	// Try Confluent
	found = a.scanForConfluent(ctx, namespace) || found

	if !found {
		a.logger.Debug("no kafka CRDs found in namespace",
			slog.String("phase", "scan"),
			slog.String("namespace", namespace),
		)
	}
}

func (a *AutoDiscovery) scanForStrimzi(ctx context.Context, namespace string) bool {
	a.logger.Debug("checking for strimzi kafka CRs",
		slog.String("phase", "scan"),
		slog.String("namespace", namespace),
		slog.String("operator", "strimzi"),
	)

	// Try v1 first, then v1beta2
	gvrs := []schema.GroupVersionResource{
		{Group: "kafka.strimzi.io", Version: "v1", Resource: "kafkas"},
		{Group: "kafka.strimzi.io", Version: "v1beta2", Resource: "kafkas"},
	}

	for _, gvr := range gvrs {
		list, err := a.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue // CRD not installed or no permission
		}

		if len(list.Items) > 0 {
			a.logger.Info("found strimzi kafka clusters",
				slog.String("phase", "discovery"),
				slog.String("namespace", namespace),
				slog.String("operator", "strimzi"),
				slog.Int("count", len(list.Items)),
				slog.String("api_version", gvr.Version),
			)

			for _, item := range list.Items {
				a.processStrimziKafka(ctx, &item)
			}
			return true
		}
	}

	a.logger.Debug("no strimzi clusters found",
		slog.String("phase", "scan"),
		slog.String("namespace", namespace),
		slog.String("operator", "strimzi"),
	)
	return false
}

func (a *AutoDiscovery) scanForConfluent(ctx context.Context, namespace string) bool {
	a.logger.Debug("checking for confluent kafka CRs",
		slog.String("phase", "scan"),
		slog.String("namespace", namespace),
		slog.String("operator", "confluent"),
	)

	gvr := schema.GroupVersionResource{
		Group:    "platform.confluent.io",
		Version:  "v1beta1",
		Resource: "kafkas",
	}

	list, err := a.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		a.logger.Debug("confluent CRDs not installed",
			slog.String("phase", "scan"),
			slog.String("namespace", namespace),
			slog.String("operator", "confluent"),
		)
		return false
	}

	if len(list.Items) > 0 {
		a.logger.Info("found confluent kafka clusters",
			slog.String("phase", "discovery"),
			slog.String("namespace", namespace),
			slog.String("operator", "confluent"),
			slog.Int("count", len(list.Items)),
		)

		for _, item := range list.Items {
			a.processConfluentKafka(ctx, &item)
		}
		return true
	}

	a.logger.Debug("no confluent clusters found",
		slog.String("phase", "scan"),
		slog.String("namespace", namespace),
		slog.String("operator", "confluent"),
	)
	return false
}

func (a *AutoDiscovery) processStrimziKafka(ctx context.Context, obj *unstructured.Unstructured) {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	key := fmt.Sprintf("%s/%s", namespace, name)

	a.logger.Info("discovered strimzi kafka cluster",
		slog.String("phase", "discovery"),
		slog.String("operator", "strimzi"),
		slog.String("cluster", name),
		slog.String("namespace", namespace),
	)

	cluster := &AutoDiscoveredCluster{
		Name:        key,
		Namespace:   namespace,
		Type:        "strimzi",
		KafkaCRName: name,
	}

	// Get status to extract bootstrap servers
	status, found, _ := unstructured.NestedMap(obj.Object, "status")
	if !found {
		a.logger.Warn("cluster not ready (no status)",
			slog.String("phase", "discovery"),
			slog.String("cluster", key),
		)
		cluster.Error = "cluster not ready"
		a.storeCluster(key, cluster)
		return
	}

	listeners, found, _ := unstructured.NestedSlice(status, "listeners")
	if !found || len(listeners) == 0 {
		a.logger.Warn("no listeners available yet",
			slog.String("phase", "discovery"),
			slog.String("cluster", key),
		)
		cluster.Error = "no listeners"
		a.storeCluster(key, cluster)
		return
	}

	// Find best listener (prefer plain/internal)
	var selectedListener map[string]interface{}
	var listenerName string
	for _, preferred := range []string{"plain", "tls", "internal"} {
		for _, l := range listeners {
			lMap, ok := l.(map[string]interface{})
			if !ok {
				continue
			}
			lName, _, _ := unstructured.NestedString(lMap, "name")
			if lName == preferred {
				selectedListener = lMap
				listenerName = lName
				break
			}
		}
		if selectedListener != nil {
			break
		}
	}

	// Fallback to first listener
	if selectedListener == nil {
		if first, ok := listeners[0].(map[string]interface{}); ok {
			selectedListener = first
			listenerName, _, _ = unstructured.NestedString(first, "name")
		}
	}

	if selectedListener == nil {
		a.logger.Error("no usable listeners found",
			slog.String("phase", "discovery"),
			slog.String("cluster", key),
		)
		cluster.Error = "no usable listeners"
		a.storeCluster(key, cluster)
		return
	}

	a.logger.Debug("selected listener",
		slog.String("cluster", key),
		slog.String("listener", listenerName),
	)

	// Get bootstrap servers
	bootstrapServers, _, _ := unstructured.NestedString(selectedListener, "bootstrapServers")
	if bootstrapServers != "" {
		cluster.Brokers = strings.Split(bootstrapServers, ",")
	} else {
		// Fallback to addresses
		addresses, _, _ := unstructured.NestedSlice(selectedListener, "addresses")
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

	a.logger.Info("  ║ 🌐 Bootstrap servers:")
	for _, broker := range cluster.Brokers {
		a.logger.Info("  ║     └─ " + broker)
	}

	// Check spec for TLS and auth
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	kafkaSpec, _, _ := unstructured.NestedMap(spec, "kafka")
	specListeners, _, _ := unstructured.NestedSlice(kafkaSpec, "listeners")

	for _, l := range specListeners {
		lMap, ok := l.(map[string]interface{})
		if !ok {
			continue
		}
		lName, _, _ := unstructured.NestedString(lMap, "name")
		if lName != listenerName {
			continue
		}

		// TLS
		tlsEnabled, found, _ := unstructured.NestedBool(lMap, "tls")
		if found && tlsEnabled {
			cluster.TLSEnabled = true
		}

		// Authentication
		auth, found, _ := unstructured.NestedMap(lMap, "authentication")
		if found {
			authType, _, _ := unstructured.NestedString(auth, "type")
			cluster.AuthType = authType
		}
		break
	}

	a.logger.Debug("cluster security config",
		slog.String("cluster", key),
		slog.Bool("tls_enabled", cluster.TLSEnabled),
		slog.String("auth_type", cluster.AuthType),
	)

	// Fetch credentials if needed
	if cluster.AuthType != "" && cluster.AuthType != "tls" {
		a.fetchStrimziCredentials(ctx, cluster, namespace)
	}

	// Fetch TLS certs if needed
	if cluster.TLSEnabled {
		a.fetchStrimziTLSCerts(ctx, cluster, namespace, name)
	}

	cluster.Ready = cluster.Error == "" && len(cluster.Brokers) > 0
	a.storeCluster(key, cluster)

	if cluster.Ready {
		a.logger.Info("strimzi cluster ready for consumption",
			slog.String("phase", "discovery"),
			slog.String("cluster", key),
			slog.Any("brokers", cluster.Brokers),
			slog.Bool("tls", cluster.TLSEnabled),
			slog.String("auth", cluster.AuthType),
		)
	} else {
		a.logger.Warn("strimzi cluster has issues",
			slog.String("phase", "discovery"),
			slog.String("cluster", key),
			slog.String("error", cluster.Error),
		)
	}

	// Notify handler
	a.notifyHandler(AutoDiscoveryEvent{
		Type:    "ready",
		Cluster: cluster,
		Message: fmt.Sprintf("Strimzi cluster %s ready with %d brokers", name, len(cluster.Brokers)),
	})
}

func (a *AutoDiscovery) fetchStrimziCredentials(ctx context.Context, cluster *AutoDiscoveredCluster, namespace string) {
	a.logger.Debug("fetching strimzi credentials",
		slog.String("phase", "credentials"),
		slog.String("cluster", cluster.Name),
		slog.String("namespace", namespace),
	)

	// Strimzi creates KafkaUser secrets with naming convention: <username>
	// Look for secrets with label strimzi.io/kind=KafkaUser
	secrets, err := a.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "strimzi.io/kind=KafkaUser",
	})
	if err != nil {
		a.logger.Warn("failed to list KafkaUser secrets",
			slog.String("cluster", cluster.Name),
			slog.Any("error", err),
		)
		return
	}

	if len(secrets.Items) == 0 {
		a.logger.Info("no KafkaUser secrets found",
			slog.String("cluster", cluster.Name),
			slog.String("hint", "create a KafkaUser CR for authentication"),
		)
		return
	}

	// Use first available user
	secret := secrets.Items[0]
	cluster.SecretName = secret.Name
	a.logger.Debug("found credential secret",
		slog.String("cluster", cluster.Name),
		slog.String("secret", secret.Name),
	)

	// SCRAM credentials
	if cluster.AuthType == "scram-sha-512" || cluster.AuthType == "scram-sha-256" {
		if username, ok := secret.Data["username"]; ok {
			cluster.Username = string(username)
		}
		if password, ok := secret.Data["password"]; ok {
			cluster.Password = string(password)
		}
		a.logger.Debug("credentials extracted",
			slog.String("cluster", cluster.Name),
			slog.String("auth_type", cluster.AuthType),
		)
	}
}

func (a *AutoDiscovery) fetchStrimziTLSCerts(ctx context.Context, cluster *AutoDiscoveredCluster, namespace, clusterName string) {
	a.logger.Debug("fetching strimzi TLS certificates",
		slog.String("phase", "tls"),
		slog.String("cluster", cluster.Name),
	)

	// Strimzi cluster CA secret: <cluster-name>-cluster-ca-cert
	caSecretName := clusterName + "-cluster-ca-cert"
	caSecret, err := a.clientset.CoreV1().Secrets(namespace).Get(ctx, caSecretName, metav1.GetOptions{})
	if err != nil {
		a.logger.Warn("CA cert secret not found",
			slog.String("cluster", cluster.Name),
			slog.String("secret", caSecretName),
			slog.Any("error", err),
		)
	} else {
		if caCert, ok := caSecret.Data["ca.crt"]; ok {
			cluster.CACert = string(caCert)
			cluster.TLSSecretName = caSecretName
			a.logger.Debug("CA certificate extracted",
				slog.String("cluster", cluster.Name),
				slog.String("secret", caSecretName),
			)
		}
	}

	// For mTLS, also get client certs from KafkaUser secret
	if cluster.AuthType == "tls" && cluster.SecretName != "" {
		userSecret, err := a.clientset.CoreV1().Secrets(namespace).Get(ctx, cluster.SecretName, metav1.GetOptions{})
		if err == nil {
			if cert, ok := userSecret.Data["user.crt"]; ok {
				cluster.ClientCert = string(cert)
			}
			if key, ok := userSecret.Data["user.key"]; ok {
				cluster.ClientKey = string(key)
			}
			a.logger.Debug("client certificates extracted",
				slog.String("cluster", cluster.Name),
				slog.String("secret", cluster.SecretName),
			)
		}
	}
}

func (a *AutoDiscovery) processConfluentKafka(ctx context.Context, obj *unstructured.Unstructured) {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	key := fmt.Sprintf("%s/%s", namespace, name)

	a.logger.Info("discovered confluent kafka cluster",
		slog.String("phase", "discovery"),
		slog.String("operator", "confluent"),
		slog.String("cluster", name),
		slog.String("namespace", namespace),
	)

	cluster := &AutoDiscoveredCluster{
		Name:        key,
		Namespace:   namespace,
		Type:        "confluent",
		KafkaCRName: name,
	}

	// Check status
	status, found, _ := unstructured.NestedMap(obj.Object, "status")
	clusterID, _, _ := unstructured.NestedString(status, "kafkaClusterID")
	if !found || clusterID == "" {
		a.logger.Warn("cluster not ready (no kafkaClusterID)",
			slog.String("phase", "discovery"),
			slog.String("cluster", key),
		)
		cluster.Error = "cluster not ready"
		a.storeCluster(key, cluster)
		return
	}

	a.logger.Debug("confluent cluster ID obtained",
		slog.String("cluster", key),
		slog.String("cluster_id", clusterID),
	)

	// Default internal bootstrap: <name>.<namespace>.svc.cluster.local:9071
	cluster.Brokers = []string{fmt.Sprintf("%s.%s.svc.cluster.local:9071", name, namespace)}

	// Check spec for TLS and auth
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")

	// TLS config
	tls, found, _ := unstructured.NestedMap(spec, "tls")
	if found {
		secretRef, _, _ := unstructured.NestedString(tls, "secretRef")
		if secretRef != "" {
			cluster.TLSEnabled = true
			cluster.TLSSecretName = secretRef
			a.fetchConfluentTLSCerts(ctx, cluster, namespace, secretRef)
		}
	}

	// Check listener TLS
	listeners, _, _ := unstructured.NestedMap(spec, "listeners")
	internal, _, _ := unstructured.NestedMap(listeners, "internal")
	if internal != nil {
		internalTLS, _, _ := unstructured.NestedMap(internal, "tls")
		if internalTLS != nil {
			enabled, _, _ := unstructured.NestedBool(internalTLS, "enabled")
			if enabled {
				cluster.TLSEnabled = true
			}
		}

		// Auth
		auth, found, _ := unstructured.NestedMap(internal, "authentication")
		if found {
			authType, _, _ := unstructured.NestedString(auth, "type")
			cluster.AuthType = authType

			// Fetch credentials from JAAS secret
			jaas, _, _ := unstructured.NestedMap(auth, "jaasConfig")
			secretRef, _, _ := unstructured.NestedString(jaas, "secretRef")
			if secretRef != "" {
				a.fetchConfluentCredentials(ctx, cluster, namespace, secretRef)
			}
		}
	}

	cluster.Ready = len(cluster.Brokers) > 0
	a.storeCluster(key, cluster)

	if cluster.Ready {
		a.logger.Info("confluent cluster ready for consumption",
			slog.String("phase", "discovery"),
			slog.String("cluster", key),
			slog.Any("brokers", cluster.Brokers),
			slog.Bool("tls", cluster.TLSEnabled),
			slog.String("auth", cluster.AuthType),
		)
	}

	// Notify handler
	a.notifyHandler(AutoDiscoveryEvent{
		Type:    "ready",
		Cluster: cluster,
		Message: fmt.Sprintf("Confluent cluster %s ready", name),
	})
}

func (a *AutoDiscovery) fetchConfluentCredentials(ctx context.Context, cluster *AutoDiscoveredCluster, namespace, secretName string) {
	a.logger.Debug("fetching confluent credentials",
		slog.String("phase", "credentials"),
		slog.String("cluster", cluster.Name),
		slog.String("secret", secretName),
	)

	secret, err := a.clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		a.logger.Warn("failed to get credentials secret",
			slog.String("cluster", cluster.Name),
			slog.String("secret", secretName),
			slog.Any("error", err),
		)
		return
	}

	cluster.SecretName = secretName

	// Try common credential keys
	for _, userKey := range []string{"username", "sasl.username", "plain.txt"} {
		if val, ok := secret.Data[userKey]; ok {
			// plain.txt format: username=x\npassword=y
			content := string(val)
			if strings.Contains(content, "=") {
				for _, line := range strings.Split(content, "\n") {
					if strings.HasPrefix(line, "username=") {
						cluster.Username = strings.TrimPrefix(line, "username=")
					}
					if strings.HasPrefix(line, "password=") {
						cluster.Password = strings.TrimPrefix(line, "password=")
					}
				}
			} else {
				cluster.Username = content
			}
			break
		}
	}

	for _, passKey := range []string{"password", "sasl.password"} {
		if val, ok := secret.Data[passKey]; ok {
			cluster.Password = string(val)
			break
		}
	}

	if cluster.Username != "" {
		a.logger.Debug("credentials extracted",
			slog.String("cluster", cluster.Name),
			slog.String("secret", secretName),
		)
	}
}

func (a *AutoDiscovery) fetchConfluentTLSCerts(ctx context.Context, cluster *AutoDiscoveredCluster, namespace, secretName string) {
	a.logger.Debug("fetching confluent TLS certificates",
		slog.String("phase", "tls"),
		slog.String("cluster", cluster.Name),
		slog.String("secret", secretName),
	)

	secret, err := a.clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		a.logger.Warn("failed to get TLS secret",
			slog.String("cluster", cluster.Name),
			slog.String("secret", secretName),
			slog.Any("error", err),
		)
		return
	}

	// Try common cert keys
	for _, caKey := range []string{"ca.crt", "tls.crt", "cacerts.pem", "ca.pem"} {
		if val, ok := secret.Data[caKey]; ok {
			cluster.CACert = string(val)
			break
		}
	}

	// Client certs
	if val, ok := secret.Data["tls.crt"]; ok {
		cluster.ClientCert = string(val)
	}
	if val, ok := secret.Data["tls.key"]; ok {
		cluster.ClientKey = string(val)
	}

	a.logger.Debug("TLS certificates extracted",
		slog.String("cluster", cluster.Name),
		slog.String("secret", secretName),
		slog.Bool("has_ca", cluster.CACert != ""),
		slog.Bool("has_client_cert", cluster.ClientCert != ""),
	)
}

func (a *AutoDiscovery) storeCluster(key string, cluster *AutoDiscoveredCluster) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clusters[key] = cluster
}

func (a *AutoDiscovery) notifyHandler(event AutoDiscoveryEvent) {
	a.mu.RLock()
	handler := a.handler
	a.mu.RUnlock()

	if handler != nil {
		handler(event)
	}
}

func (a *AutoDiscovery) watchLoop(ctx context.Context, namespaces []string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Periodic rescan
			for _, ns := range namespaces {
				select {
				case <-a.stopCh:
					return
				case <-ctx.Done():
					return
				default:
					// Quietly rescan
					a.quietScan(ctx, ns)
				}
			}
		}
	}
}

func (a *AutoDiscovery) quietScan(ctx context.Context, namespace string) {
	// Strimzi
	for _, gvr := range []schema.GroupVersionResource{
		{Group: "kafka.strimzi.io", Version: "v1", Resource: "kafkas"},
		{Group: "kafka.strimzi.io", Version: "v1beta2", Resource: "kafkas"},
	} {
		list, err := a.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, item := range list.Items {
			key := fmt.Sprintf("%s/%s", item.GetNamespace(), item.GetName())
			a.mu.RLock()
			existing := a.clusters[key]
			a.mu.RUnlock()

			// Re-process if not ready or doesn't exist
			if existing == nil || !existing.Ready {
				a.processStrimziKafka(ctx, &item)
			}
		}
		break
	}

	// Confluent
	gvr := schema.GroupVersionResource{Group: "platform.confluent.io", Version: "v1beta1", Resource: "kafkas"}
	list, err := a.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			key := fmt.Sprintf("%s/%s", item.GetNamespace(), item.GetName())
			a.mu.RLock()
			existing := a.clusters[key]
			a.mu.RUnlock()

			if existing == nil || !existing.Ready {
				a.processConfluentKafka(ctx, &item)
			}
		}
	}
}

// toClusterConfig converts an AutoDiscoveredCluster to a ClusterConfig for the receiver
func (a *AutoDiscovery) toClusterConfig(cluster *AutoDiscoveredCluster) ClusterConfig {
	groupID := a.config.GroupID
	if groupID == "" {
		groupID = "telegen-" + strings.ReplaceAll(cluster.Name, "/", "-")
	}

	cfg := Config{
		Enabled:        true,
		Brokers:        cluster.Brokers,
		GroupID:        groupID,
		ClientID:       "telegen-" + strings.ReplaceAll(cluster.Name, "/", "-"),
		Topics:         a.config.Topics,
		InitialOffset:  a.config.InitialOffset,
		UseLeaderEpoch: true,
		SessionTimeout: 30 * time.Second,
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
		Telemetry: TelemetryConfig{
			KafkaReceiverRecords:   true,
			KafkaReceiverOffsetLag: true,
			KafkaBrokerConnects:    true,
			KafkaBrokerDisconnects: true,
			KafkaBrokerReadLatency: true,
			KafkaFetchBatchMetrics: true,
		},
	}

	// Set TLS
	cfg.TLS.Enable = cluster.TLSEnabled

	// Set auth
	if cluster.AuthType == "scram-sha-512" || cluster.AuthType == "scram-sha-256" {
		cfg.Auth = AuthConfig{
			Enabled:   true,
			Mechanism: strings.ToUpper(cluster.AuthType),
			Username:  cluster.Username,
			Password:  cluster.Password,
		}
	} else if cluster.AuthType == "plain" {
		cfg.Auth = AuthConfig{
			Enabled:   true,
			Mechanism: "PLAIN",
			Username:  cluster.Username,
			Password:  cluster.Password,
		}
	}

	// Write TLS certs to temp files if available
	clusterSanitized := strings.ReplaceAll(strings.ReplaceAll(cluster.Name, "/", "-"), ":", "-")

	if cluster.CACert != "" {
		caFile := fmt.Sprintf("/tmp/telegen-kafka-%s-ca.crt", clusterSanitized)
		if err := os.WriteFile(caFile, []byte(cluster.CACert), 0600); err == nil {
			cfg.TLS.CAFile = caFile
			a.logger.Debug("wrote CA certificate to file",
				slog.String("cluster", cluster.Name),
				slog.String("file", caFile),
			)
		} else {
			a.logger.Warn("failed to write CA certificate to file",
				slog.String("cluster", cluster.Name),
				slog.Any("error", err),
			)
		}
	}

	if cluster.ClientCert != "" {
		certFile := fmt.Sprintf("/tmp/telegen-kafka-%s-client.crt", clusterSanitized)
		if err := os.WriteFile(certFile, []byte(cluster.ClientCert), 0600); err == nil {
			cfg.TLS.CertFile = certFile
			a.logger.Debug("wrote client certificate to file",
				slog.String("cluster", cluster.Name),
				slog.String("file", certFile),
			)
		}
	}

	if cluster.ClientKey != "" {
		keyFile := fmt.Sprintf("/tmp/telegen-kafka-%s-client.key", clusterSanitized)
		if err := os.WriteFile(keyFile, []byte(cluster.ClientKey), 0600); err == nil {
			cfg.TLS.KeyFile = keyFile
			a.logger.Debug("wrote client key to file",
				slog.String("cluster", cluster.Name),
				slog.String("file", keyFile),
			)
		}
	}

	return ClusterConfig{
		Name:   cluster.Name,
		Config: cfg,
	}
}

// Helper to decode base64 if needed
func decodeIfBase64(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data // Already plain text
	}
	return string(decoded)
}

// PrintDiscoverySummary logs a summary of all discovered clusters
func (a *AutoDiscovery) PrintDiscoverySummary() {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ready := 0
	clusterSummaries := make([]map[string]interface{}, 0, len(a.clusters))
	for _, c := range a.clusters {
		if c.Ready {
			ready++
		}
		clusterSummaries = append(clusterSummaries, map[string]interface{}{
			"name":    c.Name,
			"type":    c.Type,
			"ready":   c.Ready,
			"brokers": c.Brokers,
			"tls":     c.TLSEnabled,
			"auth":    c.AuthType,
			"error":   c.Error,
		})
	}

	a.logger.Info("kafka auto-discovery summary",
		slog.String("phase", "summary"),
		slog.Int("total_clusters", len(a.clusters)),
		slog.Int("ready_clusters", ready),
		slog.Any("clusters", clusterSummaries),
	)
}
