package autodiscover

import (
	"bytes"
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RuntimeDetector discovers programming language runtimes and frameworks.
type RuntimeDetector struct{}

// NewRuntimeDetector creates a new runtime detector.
func NewRuntimeDetector() *RuntimeDetector {
	return &RuntimeDetector{}
}

// Name returns the detector name.
func (d *RuntimeDetector) Name() string {
	return "runtime"
}

// Priority returns the detection priority.
func (d *RuntimeDetector) Priority() int {
	return 8
}

// Dependencies returns detector dependencies.
func (d *RuntimeDetector) Dependencies() []string {
	return []string{"process"}
}

// Detect runs runtime discovery.
func (d *RuntimeDetector) Detect(ctx context.Context) (any, error) {
	runtimes := make([]RuntimeInfo, 0)

	procDir, err := os.Open("/proc")
	if err != nil {
		return runtimes, nil
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return runtimes, nil
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		if runtime := d.detectProcessRuntime(pid); runtime != nil {
			runtimes = append(runtimes, *runtime)
		}
	}

	return runtimes, nil
}

// detectProcessRuntime detects the runtime for a process.
func (d *RuntimeDetector) detectProcessRuntime(pid int) *RuntimeInfo {
	exePath := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	target, err := os.Readlink(exePath)
	if err != nil {
		return nil
	}

	runtime := &RuntimeInfo{
		PID:           pid,
		BinaryPath:    target,
		DetectionTime: time.Now(),
	}

	// Read comm for process name
	if comm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")); err == nil {
		runtime.ProcessName = strings.TrimSpace(string(comm))
	}

	// Detect language and runtime
	d.detectLanguage(runtime, target)

	// If we detected a language, try to detect framework
	if runtime.Language != "" {
		d.detectFramework(runtime, pid)
	}

	// Skip if no language detected
	if runtime.Language == "" {
		return nil
	}

	return runtime
}

// detectLanguage detects the programming language from the binary.
func (d *RuntimeDetector) detectLanguage(runtime *RuntimeInfo, binaryPath string) {
	baseName := filepath.Base(binaryPath)

	// Check for interpreted languages by interpreter name
	switch {
	case strings.HasPrefix(baseName, "python") || baseName == "python":
		runtime.Language = "python"
		runtime.RuntimeName = "CPython"
		d.detectPythonVersion(runtime, binaryPath)
		return

	case strings.HasPrefix(baseName, "python3"):
		runtime.Language = "python"
		runtime.RuntimeName = "CPython"
		d.detectPythonVersion(runtime, binaryPath)
		return

	case baseName == "node" || baseName == "nodejs":
		runtime.Language = "javascript"
		runtime.RuntimeName = "Node.js"
		d.detectNodeVersion(runtime, binaryPath)
		return

	case baseName == "deno":
		runtime.Language = "typescript"
		runtime.RuntimeName = "Deno"
		return

	case baseName == "bun":
		runtime.Language = "javascript"
		runtime.RuntimeName = "Bun"
		return

	case baseName == "java" || strings.HasPrefix(baseName, "java"):
		runtime.Language = "java"
		runtime.RuntimeName = "JVM"
		d.detectJavaVersion(runtime, binaryPath)
		return

	case baseName == "ruby" || strings.HasPrefix(baseName, "ruby"):
		runtime.Language = "ruby"
		runtime.RuntimeName = "MRI"
		return

	case baseName == "php" || strings.HasPrefix(baseName, "php"):
		runtime.Language = "php"
		runtime.RuntimeName = "PHP"
		return

	case baseName == "dotnet":
		runtime.Language = "csharp"
		runtime.RuntimeName = ".NET"
		return

	case baseName == "perl" || strings.HasPrefix(baseName, "perl"):
		runtime.Language = "perl"
		runtime.RuntimeName = "Perl"
		return

	case baseName == "lua" || strings.HasPrefix(baseName, "lua"):
		runtime.Language = "lua"
		runtime.RuntimeName = "Lua"
		return

	case baseName == "beam.smp":
		runtime.Language = "erlang"
		runtime.RuntimeName = "BEAM"
		return
	}

	// For compiled binaries, analyze ELF
	d.detectCompiledLanguage(runtime, binaryPath)
}

// detectCompiledLanguage detects compiled language from ELF binary.
func (d *RuntimeDetector) detectCompiledLanguage(runtime *RuntimeInfo, binaryPath string) {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	// Get symbols (both dynamic and regular)
	symbols, _ := f.DynamicSymbols()
	staticSymbols, _ := f.Symbols()
	symbols = append(symbols, staticSymbols...)

	symbolNames := make(map[string]bool)
	for _, sym := range symbols {
		symbolNames[sym.Name] = true
	}

	// Check for Go
	if d.isGoRuntime(symbolNames, f) {
		runtime.Language = "go"
		runtime.RuntimeName = "Go"
		d.detectGoVersion(runtime, f)
		return
	}

	// Check for Rust
	if d.isRustRuntime(symbolNames) {
		runtime.Language = "rust"
		runtime.RuntimeName = "Rust"
		return
	}

	// Check for C++
	if d.isCppRuntime(symbolNames) {
		runtime.Language = "cpp"
		runtime.RuntimeName = "C++"
		return
	}

	// Default to C for native binaries
	if len(symbols) > 0 {
		runtime.Language = "c"
		runtime.RuntimeName = "Native"
	}
}

// isGoRuntime checks if the binary is a Go program.
func (d *RuntimeDetector) isGoRuntime(symbols map[string]bool, f *elf.File) bool {
	// Go binaries have specific symbols
	goSymbols := []string{
		"runtime.main",
		"runtime.goexit",
		"runtime.gopanic",
		"main.main",
	}

	for _, sym := range goSymbols {
		if symbols[sym] {
			return true
		}
	}

	// Check for .go.buildinfo section
	for _, section := range f.Sections {
		if section.Name == ".go.buildinfo" {
			return true
		}
	}

	return false
}

// isRustRuntime checks if the binary is a Rust program.
func (d *RuntimeDetector) isRustRuntime(symbols map[string]bool) bool {
	// Rust binaries have mangled symbols starting with _ZN
	for sym := range symbols {
		if strings.Contains(sym, "_rust_") ||
			strings.Contains(sym, "std::") ||
			strings.HasPrefix(sym, "_ZN") && strings.Contains(sym, "core") {
			return true
		}
	}
	return false
}

// isCppRuntime checks if the binary is a C++ program.
func (d *RuntimeDetector) isCppRuntime(symbols map[string]bool) bool {
	for sym := range symbols {
		// C++ mangled symbols
		if strings.HasPrefix(sym, "_Z") ||
			strings.Contains(sym, "std::") ||
			strings.Contains(sym, "__cxa_") {
			return true
		}
	}
	return false
}

// detectGoVersion extracts Go version from the binary.
func (d *RuntimeDetector) detectGoVersion(runtime *RuntimeInfo, f *elf.File) {
	// Read .go.buildinfo section
	for _, section := range f.Sections {
		if section.Name == ".go.buildinfo" {
			data, err := section.Data()
			if err != nil {
				continue
			}

			// Parse Go build info
			if idx := bytes.Index(data, []byte("go")); idx >= 0 {
				end := bytes.IndexAny(data[idx:], "\x00\n")
				if end > 0 && end < 20 {
					version := string(data[idx : idx+end])
					if strings.HasPrefix(version, "go1.") {
						runtime.RuntimeVersion = version
					}
				}
			}
			break
		}
	}
}

// detectPythonVersion detects Python version.
func (d *RuntimeDetector) detectPythonVersion(runtime *RuntimeInfo, binaryPath string) {
	// Extract version from path or binary name
	versionRegex := regexp.MustCompile(`python(\d+\.?\d*)`)
	if matches := versionRegex.FindStringSubmatch(binaryPath); len(matches) > 1 {
		runtime.RuntimeVersion = matches[1]
	}
}

// detectNodeVersion detects Node.js version.
func (d *RuntimeDetector) detectNodeVersion(runtime *RuntimeInfo, binaryPath string) {
	// Version usually in path like /usr/lib/nodejs/v16.x/
	versionRegex := regexp.MustCompile(`v(\d+\.\d+)`)
	if matches := versionRegex.FindStringSubmatch(binaryPath); len(matches) > 1 {
		runtime.RuntimeVersion = matches[1]
	}
}

// detectJavaVersion detects Java version.
func (d *RuntimeDetector) detectJavaVersion(runtime *RuntimeInfo, binaryPath string) {
	// Extract from path like /usr/lib/jvm/java-11-openjdk/
	versionRegex := regexp.MustCompile(`java-?(\d+)`)
	if matches := versionRegex.FindStringSubmatch(binaryPath); len(matches) > 1 {
		runtime.RuntimeVersion = matches[1]
	}
}

// detectFramework detects the framework used by a process.
func (d *RuntimeDetector) detectFramework(runtime *RuntimeInfo, pid int) {
	// Read command line and environment
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	cmdline, _ := os.ReadFile(cmdlinePath)
	cmdlineStr := string(cmdline)

	environPath := filepath.Join("/proc", strconv.Itoa(pid), "environ")
	environ, _ := os.ReadFile(environPath)
	environStr := string(environ)

	switch runtime.Language {
	case "go":
		d.detectGoFramework(runtime, cmdlineStr)
	case "python":
		d.detectPythonFramework(runtime, cmdlineStr, environStr)
	case "javascript", "typescript":
		d.detectNodeFramework(runtime, cmdlineStr, pid)
	case "java":
		d.detectJavaFramework(runtime, cmdlineStr)
	case "ruby":
		d.detectRubyFramework(runtime, cmdlineStr)
	}
}

// detectGoFramework detects Go frameworks.
func (d *RuntimeDetector) detectGoFramework(runtime *RuntimeInfo, cmdline string) {
	// Go frameworks are typically compiled into the binary
	// We could analyze the binary for specific symbols
	frameworks := []struct {
		pattern   string
		framework string
	}{
		{"gin", "Gin"},
		{"echo", "Echo"},
		{"fiber", "Fiber"},
		{"chi", "Chi"},
		{"gorilla", "Gorilla"},
		{"beego", "Beego"},
		{"revel", "Revel"},
	}

	for _, fw := range frameworks {
		if strings.Contains(strings.ToLower(cmdline), fw.pattern) {
			runtime.Framework = fw.framework
			return
		}
	}
}

// detectPythonFramework detects Python frameworks.
func (d *RuntimeDetector) detectPythonFramework(runtime *RuntimeInfo, cmdline, environ string) {
	combined := cmdline + environ

	frameworks := []struct {
		pattern   string
		framework string
	}{
		{"django", "Django"},
		{"flask", "Flask"},
		{"fastapi", "FastAPI"},
		{"uvicorn", "FastAPI"},
		{"gunicorn", "Gunicorn"},
		{"celery", "Celery"},
		{"tornado", "Tornado"},
		{"bottle", "Bottle"},
		{"pyramid", "Pyramid"},
		{"sanic", "Sanic"},
		{"aiohttp", "aiohttp"},
	}

	for _, fw := range frameworks {
		if strings.Contains(strings.ToLower(combined), fw.pattern) {
			runtime.Framework = fw.framework
			return
		}
	}
}

// detectNodeFramework detects Node.js frameworks.
func (d *RuntimeDetector) detectNodeFramework(runtime *RuntimeInfo, cmdline string, pid int) {
	// Check for common frameworks in command line or cwd
	frameworks := []struct {
		pattern   string
		framework string
	}{
		{"express", "Express"},
		{"nest", "NestJS"},
		{"next", "Next.js"},
		{"nuxt", "Nuxt.js"},
		{"koa", "Koa"},
		{"fastify", "Fastify"},
		{"hapi", "Hapi"},
		{"remix", "Remix"},
		{"gatsby", "Gatsby"},
		{"electron", "Electron"},
	}

	for _, fw := range frameworks {
		if strings.Contains(strings.ToLower(cmdline), fw.pattern) {
			runtime.Framework = fw.framework
			return
		}
	}

	// Check for package.json in cwd
	cwdPath := filepath.Join("/proc", strconv.Itoa(pid), "cwd")
	if cwd, err := os.Readlink(cwdPath); err == nil {
		packagePath := filepath.Join(cwd, "package.json")
		if data, err := os.ReadFile(packagePath); err == nil {
			for _, fw := range frameworks {
				if strings.Contains(strings.ToLower(string(data)), fw.pattern) {
					runtime.Framework = fw.framework
					return
				}
			}
		}
	}
}

// detectJavaFramework detects Java frameworks.
func (d *RuntimeDetector) detectJavaFramework(runtime *RuntimeInfo, cmdline string) {
	frameworks := []struct {
		pattern   string
		framework string
	}{
		{"spring", "Spring"},
		{"springboot", "Spring Boot"},
		{"spring-boot", "Spring Boot"},
		{"quarkus", "Quarkus"},
		{"micronaut", "Micronaut"},
		{"dropwizard", "Dropwizard"},
		{"vertx", "Vert.x"},
		{"play", "Play"},
		{"grails", "Grails"},
		{"struts", "Struts"},
		{"tomcat", "Tomcat"},
		{"jetty", "Jetty"},
		{"wildfly", "WildFly"},
	}

	for _, fw := range frameworks {
		if strings.Contains(strings.ToLower(cmdline), fw.pattern) {
			runtime.Framework = fw.framework
			return
		}
	}
}

// detectRubyFramework detects Ruby frameworks.
func (d *RuntimeDetector) detectRubyFramework(runtime *RuntimeInfo, cmdline string) {
	frameworks := []struct {
		pattern   string
		framework string
	}{
		{"rails", "Rails"},
		{"sinatra", "Sinatra"},
		{"hanami", "Hanami"},
		{"grape", "Grape"},
		{"roda", "Roda"},
		{"puma", "Puma"},
		{"unicorn", "Unicorn"},
		{"sidekiq", "Sidekiq"},
	}

	for _, fw := range frameworks {
		if strings.Contains(strings.ToLower(cmdline), fw.pattern) {
			runtime.Framework = fw.framework
			return
		}
	}
}
