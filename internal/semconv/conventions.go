// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package semconv provides OpenTelemetry semantic convention helpers for Telegen.
package semconv

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// Cloud provider constants
const (
	CloudProviderAWS          = "aws"
	CloudProviderGCP          = "gcp"
	CloudProviderAzure        = "azure"
	CloudProviderAlibabaCloud = "alibaba_cloud"
	CloudProviderOracleCloud  = "oracle_cloud"
	CloudProviderDigitalOcean = "digitalocean"
	CloudProviderOpenStack    = "openstack"
	CloudProviderVMware       = "vmware"
	CloudProviderNutanix      = "nutanix"
	CloudProviderOnPrem       = "on_premises"
)

// Cloud platform constants
const (
	CloudPlatformAWSEC2           = "aws_ec2"
	CloudPlatformAWSEKS           = "aws_eks"
	CloudPlatformAWSLambda        = "aws_lambda"
	CloudPlatformAWSECS           = "aws_ecs"
	CloudPlatformGCPComputeEngine = "gcp_compute_engine"
	CloudPlatformGCPGKE           = "gcp_kubernetes_engine"
	CloudPlatformGCPCloudRun      = "gcp_cloud_run"
	CloudPlatformAzureVM          = "azure_vm"
	CloudPlatformAzureAKS         = "azure_aks"
	CloudPlatformAzureFunctions   = "azure_functions"
	CloudPlatformOpenStackNova    = "openstack_nova"
	CloudPlatformVMwarevSphere    = "vmware_vsphere"
	CloudPlatformNutanixAHV       = "nutanix_ahv"
	CloudPlatformOnPrem           = "on_premises"
)

// TelegenNamespace is the service namespace for Telegen-specific attributes
const TelegenNamespace = "telegen"

// Custom attribute keys for Telegen
var (
	AttrCloudDatacenter       = attribute.Key("cloud.datacenter")
	AttrCloudClusterID        = attribute.Key("cloud.cluster.id")
	AttrCloudClusterName      = attribute.Key("cloud.cluster.name")
	AttrCloudResourcePoolID   = attribute.Key("cloud.resource_pool.id")
	AttrCloudResourcePoolName = attribute.Key("cloud.resource_pool.name")
	AttrCloudHypervisor       = attribute.Key("cloud.hypervisor")
	AttrCloudHostID           = attribute.Key("cloud.host.id")
	AttrCloudHostName         = attribute.Key("cloud.host.name")

	AttrVirtualizationType = attribute.Key("virtualization.type")
	AttrVirtualizationIsVM = attribute.Key("virtualization.is_vm")

	AttrContainerRuntimeName    = attribute.Key("container.runtime.name")
	AttrContainerRuntimeVersion = attribute.Key("container.runtime.version")

	AttrProcessLanguage     = attribute.Key("process.language")
	AttrProcessFramework    = attribute.Key("process.framework")
	AttrProcessFrameworkVer = attribute.Key("process.framework.version")
	AttrProcessType         = attribute.Key("process.type")

	AttrDatabaseType    = attribute.Key("db.type")
	AttrDatabaseVersion = attribute.Key("db.version")
	AttrDatabasePort    = attribute.Key("db.port")

	AttrMQType    = attribute.Key("messaging.type")
	AttrMQVersion = attribute.Key("messaging.version")
	AttrMQPort    = attribute.Key("messaging.port")

	AttrNetworkInterfaceName = attribute.Key("network.interface.name")
	AttrNetworkInterfaceType = attribute.Key("network.interface.type")
	AttrNetworkGateway       = attribute.Key("network.gateway")
	AttrNetworkDNSServers    = attribute.Key("network.dns.servers")
)

// CloudAttributes creates OTel resource attributes for a cloud environment
type CloudAttributes struct {
	attrs []attribute.KeyValue
}

// NewCloudAttributes creates a new CloudAttributes builder
func NewCloudAttributes() *CloudAttributes {
	return &CloudAttributes{attrs: make([]attribute.KeyValue, 0, 16)}
}

// Provider sets the cloud provider
func (ca *CloudAttributes) Provider(provider string) *CloudAttributes {
	ca.attrs = append(ca.attrs, semconv.CloudProviderKey.String(provider))
	return ca
}

// Platform sets the cloud platform
func (ca *CloudAttributes) Platform(platform string) *CloudAttributes {
	ca.attrs = append(ca.attrs, semconv.CloudPlatformKey.String(platform))
	return ca
}

// Region sets the cloud region
func (ca *CloudAttributes) Region(region string) *CloudAttributes {
	if region != "" {
		ca.attrs = append(ca.attrs, semconv.CloudRegionKey.String(region))
	}
	return ca
}

// AvailabilityZone sets the availability zone
func (ca *CloudAttributes) AvailabilityZone(zone string) *CloudAttributes {
	if zone != "" {
		ca.attrs = append(ca.attrs, semconv.CloudAvailabilityZoneKey.String(zone))
	}
	return ca
}

// AccountID sets the cloud account/project ID
func (ca *CloudAttributes) AccountID(id string) *CloudAttributes {
	if id != "" {
		ca.attrs = append(ca.attrs, semconv.CloudAccountIDKey.String(id))
	}
	return ca
}

// HostID sets the host/instance ID
func (ca *CloudAttributes) HostID(id string) *CloudAttributes {
	if id != "" {
		ca.attrs = append(ca.attrs, semconv.HostIDKey.String(id))
	}
	return ca
}

// HostName sets the hostname
func (ca *CloudAttributes) HostName(name string) *CloudAttributes {
	if name != "" {
		ca.attrs = append(ca.attrs, semconv.HostNameKey.String(name))
	}
	return ca
}

// HostType sets the instance type
func (ca *CloudAttributes) HostType(hostType string) *CloudAttributes {
	if hostType != "" {
		ca.attrs = append(ca.attrs, semconv.HostTypeKey.String(hostType))
	}
	return ca
}

// HostArch sets the host architecture
func (ca *CloudAttributes) HostArch(arch string) *CloudAttributes {
	if arch != "" {
		ca.attrs = append(ca.attrs, semconv.HostArchKey.String(arch))
	}
	return ca
}

// Build returns the accumulated attributes
func (ca *CloudAttributes) Build() []attribute.KeyValue {
	return ca.attrs
}

// ServiceAttributes creates OTel resource attributes for a discovered service
type ServiceAttributes struct {
	attrs []attribute.KeyValue
}

// NewServiceAttributes creates a new ServiceAttributes builder
func NewServiceAttributes() *ServiceAttributes {
	return &ServiceAttributes{attrs: make([]attribute.KeyValue, 0, 8)}
}

// Name sets the service name
func (sa *ServiceAttributes) Name(name string) *ServiceAttributes {
	if name != "" {
		sa.attrs = append(sa.attrs, semconv.ServiceNameKey.String(name))
	}
	return sa
}

// Namespace sets the service namespace
func (sa *ServiceAttributes) Namespace(ns string) *ServiceAttributes {
	if ns != "" {
		sa.attrs = append(sa.attrs, semconv.ServiceNamespaceKey.String(ns))
	}
	return sa
}

// Version sets the service version
func (sa *ServiceAttributes) Version(version string) *ServiceAttributes {
	if version != "" {
		sa.attrs = append(sa.attrs, semconv.ServiceVersionKey.String(version))
	}
	return sa
}

// InstanceID sets the service instance ID
func (sa *ServiceAttributes) InstanceID(id string) *ServiceAttributes {
	if id != "" {
		sa.attrs = append(sa.attrs, semconv.ServiceInstanceIDKey.String(id))
	}
	return sa
}

// Build returns the accumulated attributes
func (sa *ServiceAttributes) Build() []attribute.KeyValue {
	return sa.attrs
}

// K8sAttributes creates OTel resource attributes for Kubernetes
type K8sAttributes struct {
	attrs []attribute.KeyValue
}

// NewK8sAttributes creates a new K8sAttributes builder
func NewK8sAttributes() *K8sAttributes {
	return &K8sAttributes{attrs: make([]attribute.KeyValue, 0, 12)}
}

// ClusterName sets the Kubernetes cluster name
func (ka *K8sAttributes) ClusterName(name string) *K8sAttributes {
	if name != "" {
		ka.attrs = append(ka.attrs, semconv.K8SClusterNameKey.String(name))
	}
	return ka
}

// Namespace sets the Kubernetes namespace
func (ka *K8sAttributes) Namespace(ns string) *K8sAttributes {
	if ns != "" {
		ka.attrs = append(ka.attrs, semconv.K8SNamespaceNameKey.String(ns))
	}
	return ka
}

// PodName sets the pod name
func (ka *K8sAttributes) PodName(name string) *K8sAttributes {
	if name != "" {
		ka.attrs = append(ka.attrs, semconv.K8SPodNameKey.String(name))
	}
	return ka
}

// PodUID sets the pod UID
func (ka *K8sAttributes) PodUID(uid string) *K8sAttributes {
	if uid != "" {
		ka.attrs = append(ka.attrs, semconv.K8SPodUIDKey.String(uid))
	}
	return ka
}

// ContainerName sets the container name
func (ka *K8sAttributes) ContainerName(name string) *K8sAttributes {
	if name != "" {
		ka.attrs = append(ka.attrs, semconv.K8SContainerNameKey.String(name))
	}
	return ka
}

// DeploymentName sets the deployment name
func (ka *K8sAttributes) DeploymentName(name string) *K8sAttributes {
	if name != "" {
		ka.attrs = append(ka.attrs, semconv.K8SDeploymentNameKey.String(name))
	}
	return ka
}

// NodeName sets the node name
func (ka *K8sAttributes) NodeName(name string) *K8sAttributes {
	if name != "" {
		ka.attrs = append(ka.attrs, semconv.K8SNodeNameKey.String(name))
	}
	return ka
}

// Build returns the accumulated attributes
func (ka *K8sAttributes) Build() []attribute.KeyValue {
	return ka.attrs
}

// ProcessAttributes creates OTel resource attributes for a process
type ProcessAttributes struct {
	attrs []attribute.KeyValue
}

// NewProcessAttributes creates a new ProcessAttributes builder
func NewProcessAttributes() *ProcessAttributes {
	return &ProcessAttributes{attrs: make([]attribute.KeyValue, 0, 8)}
}

// PID sets the process ID
func (pa *ProcessAttributes) PID(pid int) *ProcessAttributes {
	pa.attrs = append(pa.attrs, semconv.ProcessPIDKey.Int(pid))
	return pa
}

// ExecutableName sets the executable name
func (pa *ProcessAttributes) ExecutableName(name string) *ProcessAttributes {
	if name != "" {
		pa.attrs = append(pa.attrs, semconv.ProcessExecutableNameKey.String(name))
	}
	return pa
}

// ExecutablePath sets the executable path
func (pa *ProcessAttributes) ExecutablePath(path string) *ProcessAttributes {
	if path != "" {
		pa.attrs = append(pa.attrs, semconv.ProcessExecutablePathKey.String(path))
	}
	return pa
}

// CommandLine sets the command line
func (pa *ProcessAttributes) CommandLine(cmdline string) *ProcessAttributes {
	if cmdline != "" {
		pa.attrs = append(pa.attrs, semconv.ProcessCommandLineKey.String(cmdline))
	}
	return pa
}

// RuntimeName sets the runtime name (go, java, python, etc.)
func (pa *ProcessAttributes) RuntimeName(name string) *ProcessAttributes {
	if name != "" {
		pa.attrs = append(pa.attrs, semconv.ProcessRuntimeNameKey.String(name))
	}
	return pa
}

// RuntimeVersion sets the runtime version
func (pa *ProcessAttributes) RuntimeVersion(version string) *ProcessAttributes {
	if version != "" {
		pa.attrs = append(pa.attrs, semconv.ProcessRuntimeVersionKey.String(version))
	}
	return pa
}

// Build returns the accumulated attributes
func (pa *ProcessAttributes) Build() []attribute.KeyValue {
	return pa.attrs
}
