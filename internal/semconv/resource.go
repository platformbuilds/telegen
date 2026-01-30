// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// Resource attribute keys following OTel semantic conventions v1.27.0
const (
	// Service attributes
	ServiceNameKey       = "service.name"
	ServiceVersionKey    = "service.version"
	ServiceNamespaceKey  = "service.namespace"
	ServiceInstanceIDKey = "service.instance.id"

	// Host attributes
	HostNameKey         = "host.name"
	HostIDKey           = "host.id"
	HostTypeKey         = "host.type"
	HostArchKey         = "host.arch"
	HostImageNameKey    = "host.image.name"
	HostImageIDKey      = "host.image.id"
	HostImageVersionKey = "host.image.version"

	// OS attributes
	OSTypeKey        = "os.type"
	OSNameKey        = "os.name"
	OSVersionKey     = "os.version"
	OSDescriptionKey = "os.description"

	// Container attributes
	ContainerIDKey        = "container.id"
	ContainerNameKey      = "container.name"
	ContainerImageNameKey = "container.image.name"
	ContainerImageTagKey  = "container.image.tag"
	ContainerImageIDKey   = "container.image.id"
	ContainerRuntimeKey   = "container.runtime"

	// Kubernetes attributes
	K8SClusterNameKey           = "k8s.cluster.name"
	K8SClusterUIDKey            = "k8s.cluster.uid"
	K8SNamespaceNameKey         = "k8s.namespace.name"
	K8SPodNameKey               = "k8s.pod.name"
	K8SPodUIDKey                = "k8s.pod.uid"
	K8SContainerNameKey         = "k8s.container.name"
	K8SContainerRestartCountKey = "k8s.container.restart_count"
	K8SReplicaSetNameKey        = "k8s.replicaset.name"
	K8SReplicaSetUIDKey         = "k8s.replicaset.uid"
	K8SDeploymentNameKey        = "k8s.deployment.name"
	K8SDeploymentUIDKey         = "k8s.deployment.uid"
	K8SStatefulSetNameKey       = "k8s.statefulset.name"
	K8SStatefulSetUIDKey        = "k8s.statefulset.uid"
	K8SDaemonSetNameKey         = "k8s.daemonset.name"
	K8SDaemonSetUIDKey          = "k8s.daemonset.uid"
	K8SJobNameKey               = "k8s.job.name"
	K8SJobUIDKey                = "k8s.job.uid"
	K8SCronJobNameKey           = "k8s.cronjob.name"
	K8SCronJobUIDKey            = "k8s.cronjob.uid"
	K8SNodeNameKey              = "k8s.node.name"
	K8SNodeUIDKey               = "k8s.node.uid"

	// Cloud attributes
	CloudProviderKey         = "cloud.provider"
	CloudAccountIDKey        = "cloud.account.id"
	CloudRegionKey           = "cloud.region"
	CloudAvailabilityZoneKey = "cloud.availability_zone"
	CloudPlatformKey         = "cloud.platform"
	CloudResourceIDKey       = "cloud.resource_id"

	// Telemetry SDK attributes
	TelemetrySDKNameKey     = "telemetry.sdk.name"
	TelemetrySDKVersionKey  = "telemetry.sdk.version"
	TelemetrySDKLanguageKey = "telemetry.sdk.language"
)

// registerResourceAttributes registers all resource semantic conventions.
func registerResourceAttributes(r *Registry) {
	// Service attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ServiceNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "Logical name of the service",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ServiceVersionKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Version string of the service API or implementation",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ServiceNamespaceKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Namespace for service.name",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ServiceInstanceIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Unique instance ID of the service",
		Stability:   StabilityStable,
	})

	// Host attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HostNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Name of the host",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HostIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Unique host ID",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HostTypeKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Type of host (cloud instance type, etc.)",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HostArchKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "CPU architecture of the host",
		Stability:   StabilityStable,
	})

	// Container attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ContainerIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Container ID",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ContainerNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Container name",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ContainerImageNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Container image name",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ContainerImageTagKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Container image tag",
		Stability:   StabilityStable,
	})

	// Kubernetes attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         K8SClusterNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Name of the Kubernetes cluster",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         K8SNamespaceNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Name of the Kubernetes namespace",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         K8SPodNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Name of the pod",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         K8SPodUIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "UID of the pod",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         K8SNodeNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Name of the node",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         K8SDeploymentNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Name of the deployment",
		Stability:   StabilityStable,
	})

	// Cloud attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         CloudProviderKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Name of the cloud provider",
		Examples:    []string{"aws", "gcp", "azure"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         CloudAccountIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Cloud account ID",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         CloudRegionKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Cloud region",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         CloudAvailabilityZoneKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Cloud availability zone",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         CloudPlatformKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Cloud platform (aws_ec2, gcp_gke, etc.)",
		Stability:   StabilityStable,
	})
}

// ResourceAttributes provides a builder for OTel resource attributes.
type ResourceAttributes struct {
	attrs []attribute.KeyValue
}

// NewResourceAttributes creates a new resource attribute builder.
func NewResourceAttributes() *ResourceAttributes {
	return &ResourceAttributes{attrs: make([]attribute.KeyValue, 0, 24)}
}

// ServiceName sets the service name.
func (r *ResourceAttributes) ServiceName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.ServiceNameKey.String(name))
	}
	return r
}

// ServiceVersion sets the service version.
func (r *ResourceAttributes) ServiceVersion(version string) *ResourceAttributes {
	if version != "" {
		r.attrs = append(r.attrs, semconv.ServiceVersionKey.String(version))
	}
	return r
}

// ServiceNamespace sets the service namespace.
func (r *ResourceAttributes) ServiceNamespace(ns string) *ResourceAttributes {
	if ns != "" {
		r.attrs = append(r.attrs, semconv.ServiceNamespaceKey.String(ns))
	}
	return r
}

// ServiceInstanceID sets the service instance ID.
func (r *ResourceAttributes) ServiceInstanceID(id string) *ResourceAttributes {
	if id != "" {
		r.attrs = append(r.attrs, semconv.ServiceInstanceIDKey.String(id))
	}
	return r
}

// HostName sets the host name.
func (r *ResourceAttributes) HostName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.HostNameKey.String(name))
	}
	return r
}

// HostID sets the host ID.
func (r *ResourceAttributes) HostID(id string) *ResourceAttributes {
	if id != "" {
		r.attrs = append(r.attrs, semconv.HostIDKey.String(id))
	}
	return r
}

// HostType sets the host type.
func (r *ResourceAttributes) HostType(hostType string) *ResourceAttributes {
	if hostType != "" {
		r.attrs = append(r.attrs, semconv.HostTypeKey.String(hostType))
	}
	return r
}

// HostArch sets the host architecture.
func (r *ResourceAttributes) HostArch(arch string) *ResourceAttributes {
	if arch != "" {
		r.attrs = append(r.attrs, semconv.HostArchKey.String(arch))
	}
	return r
}

// ContainerID sets the container ID.
func (r *ResourceAttributes) ContainerID(id string) *ResourceAttributes {
	if id != "" {
		r.attrs = append(r.attrs, semconv.ContainerIDKey.String(id))
	}
	return r
}

// ContainerName sets the container name.
func (r *ResourceAttributes) ContainerName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.ContainerNameKey.String(name))
	}
	return r
}

// ContainerImageName sets the container image name.
func (r *ResourceAttributes) ContainerImageName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.ContainerImageNameKey.String(name))
	}
	return r
}

// ContainerImageTag sets the container image tag.
func (r *ResourceAttributes) ContainerImageTag(tag string) *ResourceAttributes {
	if tag != "" {
		r.attrs = append(r.attrs, semconv.ContainerImageTags(tag))
	}
	return r
}

// K8sClusterName sets the Kubernetes cluster name.
func (r *ResourceAttributes) K8sClusterName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SClusterNameKey.String(name))
	}
	return r
}

// K8sNamespaceName sets the Kubernetes namespace name.
func (r *ResourceAttributes) K8sNamespaceName(ns string) *ResourceAttributes {
	if ns != "" {
		r.attrs = append(r.attrs, semconv.K8SNamespaceNameKey.String(ns))
	}
	return r
}

// K8sPodName sets the Kubernetes pod name.
func (r *ResourceAttributes) K8sPodName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SPodNameKey.String(name))
	}
	return r
}

// K8sPodUID sets the Kubernetes pod UID.
func (r *ResourceAttributes) K8sPodUID(uid string) *ResourceAttributes {
	if uid != "" {
		r.attrs = append(r.attrs, semconv.K8SPodUIDKey.String(uid))
	}
	return r
}

// K8sNodeName sets the Kubernetes node name.
func (r *ResourceAttributes) K8sNodeName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SNodeNameKey.String(name))
	}
	return r
}

// K8sDeploymentName sets the Kubernetes deployment name.
func (r *ResourceAttributes) K8sDeploymentName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SDeploymentNameKey.String(name))
	}
	return r
}

// K8sReplicaSetName sets the Kubernetes replicaset name.
func (r *ResourceAttributes) K8sReplicaSetName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SReplicaSetNameKey.String(name))
	}
	return r
}

// K8sStatefulSetName sets the Kubernetes statefulset name.
func (r *ResourceAttributes) K8sStatefulSetName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SStatefulSetNameKey.String(name))
	}
	return r
}

// K8sDaemonSetName sets the Kubernetes daemonset name.
func (r *ResourceAttributes) K8sDaemonSetName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SDaemonSetNameKey.String(name))
	}
	return r
}

// K8sJobName sets the Kubernetes job name.
func (r *ResourceAttributes) K8sJobName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SJobNameKey.String(name))
	}
	return r
}

// K8sCronJobName sets the Kubernetes cronjob name.
func (r *ResourceAttributes) K8sCronJobName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SCronJobNameKey.String(name))
	}
	return r
}

// K8sContainerName sets the Kubernetes container name.
func (r *ResourceAttributes) K8sContainerName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.K8SContainerNameKey.String(name))
	}
	return r
}

// CloudProvider sets the cloud provider.
func (r *ResourceAttributes) CloudProvider(provider string) *ResourceAttributes {
	if provider != "" {
		r.attrs = append(r.attrs, semconv.CloudProviderKey.String(provider))
	}
	return r
}

// CloudAccountID sets the cloud account ID.
func (r *ResourceAttributes) CloudAccountID(id string) *ResourceAttributes {
	if id != "" {
		r.attrs = append(r.attrs, semconv.CloudAccountIDKey.String(id))
	}
	return r
}

// CloudRegion sets the cloud region.
func (r *ResourceAttributes) CloudRegion(region string) *ResourceAttributes {
	if region != "" {
		r.attrs = append(r.attrs, semconv.CloudRegionKey.String(region))
	}
	return r
}

// CloudAvailabilityZone sets the cloud availability zone.
func (r *ResourceAttributes) CloudAvailabilityZone(zone string) *ResourceAttributes {
	if zone != "" {
		r.attrs = append(r.attrs, semconv.CloudAvailabilityZoneKey.String(zone))
	}
	return r
}

// CloudPlatform sets the cloud platform.
func (r *ResourceAttributes) CloudPlatform(platform string) *ResourceAttributes {
	if platform != "" {
		r.attrs = append(r.attrs, semconv.CloudPlatformKey.String(platform))
	}
	return r
}

// OSType sets the OS type.
func (r *ResourceAttributes) OSType(osType string) *ResourceAttributes {
	if osType != "" {
		r.attrs = append(r.attrs, semconv.OSTypeKey.String(osType))
	}
	return r
}

// OSName sets the OS name.
func (r *ResourceAttributes) OSName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.OSNameKey.String(name))
	}
	return r
}

// OSVersion sets the OS version.
func (r *ResourceAttributes) OSVersion(version string) *ResourceAttributes {
	if version != "" {
		r.attrs = append(r.attrs, semconv.OSVersionKey.String(version))
	}
	return r
}

// TelemetrySDKName sets the telemetry SDK name.
func (r *ResourceAttributes) TelemetrySDKName(name string) *ResourceAttributes {
	if name != "" {
		r.attrs = append(r.attrs, semconv.TelemetrySDKNameKey.String(name))
	}
	return r
}

// TelemetrySDKVersion sets the telemetry SDK version.
func (r *ResourceAttributes) TelemetrySDKVersion(version string) *ResourceAttributes {
	if version != "" {
		r.attrs = append(r.attrs, semconv.TelemetrySDKVersionKey.String(version))
	}
	return r
}

// TelemetrySDKLanguage sets the telemetry SDK language.
func (r *ResourceAttributes) TelemetrySDKLanguage(lang string) *ResourceAttributes {
	if lang != "" {
		r.attrs = append(r.attrs, semconv.TelemetrySDKLanguageKey.String(lang))
	}
	return r
}

// Build returns the accumulated attributes.
func (r *ResourceAttributes) Build() []attribute.KeyValue {
	return r.attrs
}
