package autodiscover

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DatabaseDetector discovers database services.
type DatabaseDetector struct{}

// NewDatabaseDetector creates a new database detector.
func NewDatabaseDetector() *DatabaseDetector {
	return &DatabaseDetector{}
}

// Name returns the detector name.
func (d *DatabaseDetector) Name() string {
	return "database"
}

// Priority returns the detection priority.
func (d *DatabaseDetector) Priority() int {
	return 6
}

// Dependencies returns detector dependencies.
func (d *DatabaseDetector) Dependencies() []string {
	return []string{"network", "process"}
}

// Detect runs database discovery.
func (d *DatabaseDetector) Detect(ctx context.Context) (any, error) {
	databases := make([]DatabaseInfo, 0)

	// Get listening ports from context or detect
	listeningPorts := d.getListeningPorts()

	// Check known database ports
	for _, port := range listeningPorts {
		if db := d.identifyDatabase(port); db != nil {
			databases = append(databases, *db)
		}
	}

	// Also check for database processes
	processDatabases := d.detectDatabaseProcesses()
	databases = append(databases, processDatabases...)

	// Deduplicate by type and port
	databases = d.deduplicateDatabases(databases)

	return databases, nil
}

// getListeningPorts gets listening ports from /proc/net.
func (d *DatabaseDetector) getListeningPorts() []ListeningPort {
	ports := make([]ListeningPort, 0)

	// Parse TCP ports
	d.parseProcNetForPorts("/proc/net/tcp", "tcp", false, &ports)
	d.parseProcNetForPorts("/proc/net/tcp6", "tcp", true, &ports)

	return ports
}

// parseProcNetForPorts parses /proc/net files for listening ports.
func (d *DatabaseDetector) parseProcNetForPorts(path, protocol string, ipv6 bool, ports *[]ListeningPort) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		// Only listening sockets
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

		*ports = append(*ports, ListeningPort{
			Port:     int(portNum),
			Protocol: protocol,
			IPv6:     ipv6,
		})
	}
}

// identifyDatabase identifies a database from a listening port.
func (d *DatabaseDetector) identifyDatabase(port ListeningPort) *DatabaseInfo {
	// Map of ports to database types
	portToDatabase := map[int]struct {
		dbType    DatabaseType
		name      string
		version   string
		connector func(int) *DatabaseInfo
	}{
		5432:  {DatabaseTypePostgreSQL, "PostgreSQL", "", nil},
		3306:  {DatabaseTypeMySQL, "MySQL/MariaDB", "", nil},
		1433:  {DatabaseTypeSQLServer, "SQL Server", "", nil},
		1521:  {DatabaseTypeOracle, "Oracle", "", nil},
		27017: {DatabaseTypeMongoDB, "MongoDB", "", nil},
		27018: {DatabaseTypeMongoDB, "MongoDB", "", nil},
		27019: {DatabaseTypeMongoDB, "MongoDB", "", nil},
		6379:  {DatabaseTypeRedis, "Redis", "", nil},
		9042:  {DatabaseTypeCassandra, "Cassandra", "", nil},
		9160:  {DatabaseTypeCassandra, "Cassandra", "", nil},
		9200:  {DatabaseTypeElasticsearch, "Elasticsearch", "", nil},
		9300:  {DatabaseTypeElasticsearch, "Elasticsearch", "", nil},
		5984:  {DatabaseTypeCouchDB, "CouchDB", "", nil},
		11211: {DatabaseTypeMemcached, "Memcached", "", nil},
		2181:  {DatabaseTypeZooKeeper, "ZooKeeper", "", nil},
		8529:  {DatabaseTypeArangoDB, "ArangoDB", "", nil},
		7474:  {DatabaseTypeNeo4j, "Neo4j", "", nil},
		7687:  {DatabaseTypeNeo4j, "Neo4j", "", nil},
		8086:  {DatabaseTypeInfluxDB, "InfluxDB", "", nil},
		9000:  {DatabaseTypeClickHouse, "ClickHouse", "", nil},
		8123:  {DatabaseTypeClickHouse, "ClickHouse", "", nil},
		26257: {DatabaseTypeCockroachDB, "CockroachDB", "", nil},
		4000:  {DatabaseTypeTiDB, "TiDB", "", nil},
	}

	if db, ok := portToDatabase[port.Port]; ok {
		return &DatabaseInfo{
			Type:          db.dbType,
			Name:          db.name,
			Port:          port.Port,
			Host:          "localhost",
			Detected:      true,
			DetectionTime: time.Now(),
			IsLocal:       true,
		}
	}

	return nil
}

// detectDatabaseProcesses detects databases by process patterns.
func (d *DatabaseDetector) detectDatabaseProcesses() []DatabaseInfo {
	databases := make([]DatabaseInfo, 0)

	// Process name patterns
	patterns := map[string]DatabaseType{
		"postgres":      DatabaseTypePostgreSQL,
		"postmaster":    DatabaseTypePostgreSQL,
		"mysqld":        DatabaseTypeMySQL,
		"mariadbd":      DatabaseTypeMySQL,
		"mongod":        DatabaseTypeMongoDB,
		"mongos":        DatabaseTypeMongoDB,
		"redis-server":  DatabaseTypeRedis,
		"cassandra":     DatabaseTypeCassandra,
		"elasticsearch": DatabaseTypeElasticsearch,
		"couchdb":       DatabaseTypeCouchDB,
		"memcached":     DatabaseTypeMemcached,
		"zookeeper":     DatabaseTypeZooKeeper,
		"arangod":       DatabaseTypeArangoDB,
		"neo4j":         DatabaseTypeNeo4j,
		"influxd":       DatabaseTypeInfluxDB,
		"clickhouse":    DatabaseTypeClickHouse,
		"cockroach":     DatabaseTypeCockroachDB,
		"tidb-server":   DatabaseTypeTiDB,
		"sqlservr":      DatabaseTypeSQLServer,
		"oracle":        DatabaseTypeOracle,
		"tnslsnr":       DatabaseTypeOracle,
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return databases
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return databases
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		// Read process command name
		commPath := filepath.Join("/proc", entry, "comm")
		comm, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		processName := strings.TrimSpace(string(comm))

		for pattern, dbType := range patterns {
			if strings.Contains(strings.ToLower(processName), pattern) {
				// Get additional info
				db := DatabaseInfo{
					Type:          dbType,
					Name:          getDatabaseName(dbType),
					Detected:      true,
					DetectionTime: time.Now(),
					IsLocal:       true,
					PID:           pid,
					ProcessName:   processName,
				}

				// Try to get version from cmdline or exe
				d.enrichDatabaseInfo(&db, pid)

				databases = append(databases, db)
				break
			}
		}
	}

	return databases
}

// enrichDatabaseInfo adds additional information to a database entry.
func (d *DatabaseDetector) enrichDatabaseInfo(db *DatabaseInfo, pid int) {
	// Read command line
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	if cmdline, err := os.ReadFile(cmdlinePath); err == nil {
		args := strings.Split(string(cmdline), "\x00")
		db.CommandLine = strings.Join(args, " ")

		// Extract config file or data directory from args
		for i, arg := range args {
			switch {
			case arg == "-D" || arg == "--datadir":
				if i+1 < len(args) {
					db.DataDir = args[i+1]
				}
			case strings.HasPrefix(arg, "-D"):
				db.DataDir = strings.TrimPrefix(arg, "-D")
			case strings.HasPrefix(arg, "--datadir="):
				db.DataDir = strings.TrimPrefix(arg, "--datadir=")
			case arg == "-c" || arg == "--config":
				if i+1 < len(args) {
					db.ConfigFile = args[i+1]
				}
			case strings.HasPrefix(arg, "--config="):
				db.ConfigFile = strings.TrimPrefix(arg, "--config=")
			}
		}
	}

	// Try to detect version from binary
	exePath := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	if target, err := os.Readlink(exePath); err == nil {
		db.BinaryPath = target
	}

	// Try to get listening port
	db.Port = d.getProcessListeningPort(pid)
}

// getProcessListeningPort finds the port a process is listening on.
func (d *DatabaseDetector) getProcessListeningPort(pid int) int {
	// Get all socket inodes for this process
	fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(fdPath)
	if err != nil {
		return 0
	}

	inodes := make(map[uint64]bool)
	for _, fd := range fds {
		linkPath := filepath.Join(fdPath, fd.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}

		if strings.HasPrefix(target, "socket:[") {
			inodeStr := strings.TrimPrefix(strings.TrimSuffix(target, "]"), "socket:[")
			if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
				inodes[inode] = true
			}
		}
	}

	// Find listening ports with matching inodes
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		// Only listening sockets
		if fields[3] != "0A" {
			continue
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		if inodes[inode] {
			localAddr := fields[1]
			parts := strings.Split(localAddr, ":")
			if len(parts) == 2 {
				if port, err := strconv.ParseInt(parts[1], 16, 32); err == nil {
					return int(port)
				}
			}
		}
	}

	return 0
}

// deduplicateDatabases removes duplicate database entries.
func (d *DatabaseDetector) deduplicateDatabases(databases []DatabaseInfo) []DatabaseInfo {
	seen := make(map[string]bool)
	result := make([]DatabaseInfo, 0)

	for _, db := range databases {
		key := string(db.Type) + ":" + strconv.Itoa(db.Port)
		if db.Port == 0 {
			key = string(db.Type) + ":" + db.ProcessName
		}

		if !seen[key] {
			seen[key] = true
			result = append(result, db)
		}
	}

	return result
}

// getDatabaseName returns a human-readable name for a database type.
func getDatabaseName(dbType DatabaseType) string {
	names := map[DatabaseType]string{
		DatabaseTypePostgreSQL:    "PostgreSQL",
		DatabaseTypeMySQL:         "MySQL",
		DatabaseTypeSQLServer:     "SQL Server",
		DatabaseTypeOracle:        "Oracle",
		DatabaseTypeMongoDB:       "MongoDB",
		DatabaseTypeRedis:         "Redis",
		DatabaseTypeCassandra:     "Cassandra",
		DatabaseTypeElasticsearch: "Elasticsearch",
		DatabaseTypeCouchDB:       "CouchDB",
		DatabaseTypeMemcached:     "Memcached",
		DatabaseTypeZooKeeper:     "ZooKeeper",
		DatabaseTypeArangoDB:      "ArangoDB",
		DatabaseTypeNeo4j:         "Neo4j",
		DatabaseTypeInfluxDB:      "InfluxDB",
		DatabaseTypeClickHouse:    "ClickHouse",
		DatabaseTypeCockroachDB:   "CockroachDB",
		DatabaseTypeTiDB:          "TiDB",
	}

	if name, ok := names[dbType]; ok {
		return name
	}
	return string(dbType)
}

// CheckDatabaseConnectivity attempts to connect to a database.
func CheckDatabaseConnectivity(db *DatabaseInfo, timeout time.Duration) bool {
	if db.Port == 0 {
		return false
	}

	addr := net.JoinHostPort(db.Host, strconv.Itoa(db.Port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
