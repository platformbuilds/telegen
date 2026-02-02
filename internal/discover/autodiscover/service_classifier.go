package autodiscover

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ServiceClassifier classifies discovered services by type.
type ServiceClassifier struct{}

// NewServiceClassifier creates a new service classifier.
func NewServiceClassifier() *ServiceClassifier {
	return &ServiceClassifier{}
}

// Name returns the classifier name.
func (c *ServiceClassifier) Name() string {
	return "service_classifier"
}

// Priority returns the classification priority.
func (c *ServiceClassifier) Priority() int {
	return 10 // Run after all detectors
}

// Dependencies returns classifier dependencies.
func (c *ServiceClassifier) Dependencies() []string {
	return []string{"network", "runtime", "database", "message_queue"}
}

// Detect runs service classification.
func (c *ServiceClassifier) Detect(ctx context.Context) (any, error) {
	services := make([]ServiceInfo, 0)

	// Get all processes with listening ports
	listeningPorts := c.getListeningPorts()

	for _, port := range listeningPorts {
		if port.PID == 0 {
			continue
		}

		service := c.classifyService(port)
		if service != nil {
			services = append(services, *service)
		}
	}

	return services, nil
}

// getListeningPorts gets all listening ports with process info.
func (c *ServiceClassifier) getListeningPorts() []ListeningPort {
	ports := make([]ListeningPort, 0)

	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return ports
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		if fields[3] != "0A" {
			continue
		}

		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		portNum, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}

		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		lp := ListeningPort{
			Port:     int(portNum),
			Protocol: "tcp",
			Inode:    inode,
		}

		// Find process
		lp.PID, lp.ProcessName = c.findProcessByInode(inode)

		ports = append(ports, lp)
	}

	return ports
}

// findProcessByInode finds the process that owns a socket.
func (c *ServiceClassifier) findProcessByInode(inode uint64) (int, string) {
	if inode == 0 {
		return 0, ""
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return 0, ""
	}
	defer func() { _ = procDir.Close() }()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return 0, ""
	}

	targetSocket := "socket:[" + strconv.FormatUint(inode, 10) + "]"

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		fdPath := filepath.Join("/proc", entry, "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			linkPath := filepath.Join(fdPath, fd.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			if target == targetSocket {
				commPath := filepath.Join("/proc", entry, "comm")
				if comm, err := os.ReadFile(commPath); err == nil {
					return pid, strings.TrimSpace(string(comm))
				}
				return pid, ""
			}
		}
	}

	return 0, ""
}

// classifyService classifies a service by its port and process.
func (c *ServiceClassifier) classifyService(port ListeningPort) *ServiceInfo {
	service := &ServiceInfo{
		Name:          port.ProcessName,
		Port:          port.Port,
		PID:           port.PID,
		Protocol:      port.Protocol,
		DetectionTime: time.Now(),
	}

	// First, check known port classifications
	if svcType := c.classifyByPort(port.Port); svcType != "" {
		service.Type = svcType
		service.Category = c.getCategoryForType(svcType)
	}

	// Then, refine by process name
	if processType := c.classifyByProcess(port.ProcessName, port.PID); processType != "" {
		service.Type = processType
		service.Category = c.getCategoryForType(processType)
	}

	// Get additional metadata
	c.enrichServiceInfo(service, port.PID)

	return service
}

// classifyByPort classifies a service by its port number.
func (c *ServiceClassifier) classifyByPort(port int) ServiceType {
	portClassifications := map[int]ServiceType{
		// HTTP/API
		80:   ServiceTypeHTTPAPI,
		443:  ServiceTypeHTTPAPI,
		8080: ServiceTypeHTTPAPI,
		8443: ServiceTypeHTTPAPI,
		3000: ServiceTypeHTTPAPI,
		8000: ServiceTypeHTTPAPI,

		// gRPC
		50051: ServiceTypeGRPC,

		// GraphQL (commonly on these ports)
		4000: ServiceTypeGraphQL,

		// Databases
		5432:  ServiceTypeDatabase,
		3306:  ServiceTypeDatabase,
		27017: ServiceTypeDatabase,
		6379:  ServiceTypeDatabase,
		9200:  ServiceTypeDatabase,

		// Message Queues
		9092: ServiceTypeQueue,
		5672: ServiceTypeQueue,
		4222: ServiceTypeQueue,
		6650: ServiceTypeQueue,

		// Metrics
		9090: ServiceTypeMetrics,
		9100: ServiceTypeMetrics,

		// Tracing
		14268: ServiceTypeTracing,
		4317:  ServiceTypeTracing,
		4318:  ServiceTypeTracing,

		// Logging
		5044: ServiceTypeLogging,
		9600: ServiceTypeLogging,

		// DNS
		53: ServiceTypeDNS,

		// Proxy/LB
		8081: ServiceTypeProxy,

		// Auth
		8888: ServiceTypeAuth,
	}

	if svcType, ok := portClassifications[port]; ok {
		return svcType
	}
	return ""
}

// classifyByProcess classifies a service by its process name.
func (c *ServiceClassifier) classifyByProcess(processName string, pid int) ServiceType {
	lower := strings.ToLower(processName)

	// HTTP servers
	httpServers := []string{
		"nginx", "apache", "httpd", "caddy", "traefik",
		"envoy", "haproxy", "lighttpd",
	}
	for _, srv := range httpServers {
		if strings.Contains(lower, srv) {
			return ServiceTypeProxy
		}
	}

	// Web frameworks (likely HTTP API)
	webFrameworks := []string{
		"gunicorn", "uvicorn", "node", "java",
		"rails", "django", "flask", "express",
	}
	for _, fw := range webFrameworks {
		if strings.Contains(lower, fw) {
			return ServiceTypeHTTPAPI
		}
	}

	// Databases
	databases := []string{
		"postgres", "mysql", "mariadbd", "mongod",
		"redis-server", "elasticsearch", "cassandra",
	}
	for _, db := range databases {
		if strings.Contains(lower, db) {
			return ServiceTypeDatabase
		}
	}

	// Message queues
	queues := []string{
		"kafka", "rabbitmq", "nats", "pulsar", "activemq",
	}
	for _, q := range queues {
		if strings.Contains(lower, q) {
			return ServiceTypeQueue
		}
	}

	// Background workers
	workers := []string{
		"celery", "sidekiq", "resque", "worker",
	}
	for _, w := range workers {
		if strings.Contains(lower, w) {
			return ServiceTypeWorker
		}
	}

	// Schedulers
	schedulers := []string{
		"cron", "airflow", "luigi", "scheduler",
	}
	for _, s := range schedulers {
		if strings.Contains(lower, s) {
			return ServiceTypeScheduler
		}
	}

	// Monitoring
	monitoring := []string{
		"prometheus", "grafana", "telegraf", "collectd",
		"node_exporter", "exporters",
	}
	for _, m := range monitoring {
		if strings.Contains(lower, m) {
			return ServiceTypeMetrics
		}
	}

	// Check command line for more context
	cmdline := c.getProcessCmdline(pid)
	return c.classifyByCmdline(cmdline)
}

// classifyByCmdline classifies by command line arguments.
func (c *ServiceClassifier) classifyByCmdline(cmdline string) ServiceType {
	lower := strings.ToLower(cmdline)

	// Check for gRPC
	if strings.Contains(lower, "grpc") {
		return ServiceTypeGRPC
	}

	// Check for GraphQL
	if strings.Contains(lower, "graphql") {
		return ServiceTypeGraphQL
	}

	// Check for worker patterns
	if strings.Contains(lower, "worker") || strings.Contains(lower, "consumer") {
		return ServiceTypeWorker
	}

	// Check for gateway patterns
	if strings.Contains(lower, "gateway") || strings.Contains(lower, "api-gateway") {
		return ServiceTypeGateway
	}

	return ""
}

// getCategoryForType returns the category for a service type.
func (c *ServiceClassifier) getCategoryForType(svcType ServiceType) string {
	categories := map[ServiceType]string{
		ServiceTypeHTTPAPI:   "api",
		ServiceTypeGRPC:      "api",
		ServiceTypeGraphQL:   "api",
		ServiceTypeDatabase:  "data",
		ServiceTypeCache:     "data",
		ServiceTypeQueue:     "messaging",
		ServiceTypeWorker:    "compute",
		ServiceTypeScheduler: "compute",
		ServiceTypeBatch:     "compute",
		ServiceTypeMetrics:   "observability",
		ServiceTypeTracing:   "observability",
		ServiceTypeLogging:   "observability",
		ServiceTypeProxy:     "network",
		ServiceTypeLB:        "network",
		ServiceTypeGateway:   "network",
		ServiceTypeDNS:       "network",
		ServiceTypeAuth:      "security",
		ServiceTypeStreaming: "messaging",
	}

	if cat, ok := categories[svcType]; ok {
		return cat
	}
	return "unknown"
}

// enrichServiceInfo adds additional metadata to a service.
func (c *ServiceClassifier) enrichServiceInfo(service *ServiceInfo, pid int) {
	if pid == 0 {
		return
	}

	// Get command line
	service.CommandLine = c.getProcessCmdline(pid)

	// Get working directory
	cwdPath := filepath.Join("/proc", strconv.Itoa(pid), "cwd")
	if cwd, err := os.Readlink(cwdPath); err == nil {
		service.WorkingDir = cwd
	}

	// Get environment hints
	environPath := filepath.Join("/proc", strconv.Itoa(pid), "environ")
	if environ, err := os.ReadFile(environPath); err == nil {
		service.Environment = c.extractRelevantEnv(string(environ))
	}

	// Try to determine version from environment or config
	service.Version = c.detectServiceVersion(service)

	// Check for health endpoint
	service.HealthEndpoint = c.guessHealthEndpoint(service.Port)

	// Determine if it's likely an internal or external service
	service.IsInternal = c.isInternalService(service)
}

// getProcessCmdline gets the command line for a process.
func (c *ServiceClassifier) getProcessCmdline(pid int) string {
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	if data, err := os.ReadFile(cmdlinePath); err == nil {
		return strings.Join(strings.Split(string(data), "\x00"), " ")
	}
	return ""
}

// extractRelevantEnv extracts relevant environment variables.
func (c *ServiceClassifier) extractRelevantEnv(environ string) map[string]string {
	result := make(map[string]string)

	relevantVars := []string{
		"SERVICE_NAME", "APP_NAME", "SERVICE_VERSION", "APP_VERSION",
		"PORT", "HOST", "BIND_ADDRESS",
		"DATABASE_URL", "REDIS_URL", "KAFKA_BROKERS",
		"LOG_LEVEL", "DEBUG",
		"OTEL_SERVICE_NAME", "OTEL_EXPORTER_OTLP_ENDPOINT",
		"DD_SERVICE", "DD_VERSION",
	}

	pairs := strings.Split(environ, "\x00")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		for _, relevant := range relevantVars {
			if strings.EqualFold(key, relevant) {
				result[key] = parts[1]
				break
			}
		}
	}

	return result
}

// detectServiceVersion tries to detect service version.
func (c *ServiceClassifier) detectServiceVersion(service *ServiceInfo) string {
	// Check environment variables
	for key, value := range service.Environment {
		if strings.Contains(strings.ToLower(key), "version") {
			return value
		}
	}
	return ""
}

// guessHealthEndpoint guesses a health check endpoint.
func (c *ServiceClassifier) guessHealthEndpoint(port int) string {
	if port == 0 {
		return ""
	}

	// Common health endpoints
	endpoints := []string{
		"/health",
		"/healthz",
		"/ready",
		"/readyz",
		"/live",
		"/livez",
		"/status",
		"/_health",
	}

	// Return the most common one
	return endpoints[0]
}

// isInternalService determines if a service is internal.
func (c *ServiceClassifier) isInternalService(service *ServiceInfo) bool {
	// High ports are typically internal
	if service.Port > 8000 && service.Port < 65000 {
		return true
	}

	// Metrics and monitoring are internal
	if service.Category == "observability" {
		return true
	}

	// Workers and schedulers are internal
	if service.Type == ServiceTypeWorker || service.Type == ServiceTypeScheduler {
		return true
	}

	return false
}

// ServiceType constants for classification.
const (
	ServiceTypeHTTPAPI   ServiceType = "http_api"
	ServiceTypeGRPC      ServiceType = "grpc"
	ServiceTypeGraphQL   ServiceType = "graphql"
	ServiceTypeDatabase  ServiceType = "database"
	ServiceTypeCache     ServiceType = "cache"
	ServiceTypeQueue     ServiceType = "message_queue"
	ServiceTypeWorker    ServiceType = "worker"
	ServiceTypeScheduler ServiceType = "scheduler"
	ServiceTypeBatch     ServiceType = "batch"
	ServiceTypeMetrics   ServiceType = "metrics"
	ServiceTypeTracing   ServiceType = "tracing"
	ServiceTypeLogging   ServiceType = "logging"
	ServiceTypeProxy     ServiceType = "proxy"
	ServiceTypeLB        ServiceType = "load_balancer"
	ServiceTypeGateway   ServiceType = "gateway"
	ServiceTypeDNS       ServiceType = "dns"
	ServiceTypeAuth      ServiceType = "auth"
	ServiceTypeStreaming ServiceType = "streaming"
)

// ServiceInfo represents a classified service.
type ServiceInfo struct {
	Name           string            `json:"name"`
	Type           ServiceType       `json:"type"`
	Category       string            `json:"category"`
	Port           int               `json:"port"`
	Protocol       string            `json:"protocol"`
	PID            int               `json:"pid"`
	Version        string            `json:"version,omitempty"`
	CommandLine    string            `json:"command_line,omitempty"`
	WorkingDir     string            `json:"working_dir,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	HealthEndpoint string            `json:"health_endpoint,omitempty"`
	IsInternal     bool              `json:"is_internal"`
	DetectionTime  time.Time         `json:"detection_time"`
}
