#!/bin/bash
# Telegen Java OpenJ9 Profiling Validation Script
# This script validates that Java profiling is correctly configured

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="${1:-default}"
DEPLOYMENT_NAME="${2:-java-app-openj9}"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}Telegen Java OpenJ9 Profiling Validation${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "ok" ]; then
        echo -e "${GREEN}✓${NC} $message"
    elif [ "$status" = "warning" ]; then
        echo -e "${YELLOW}⚠${NC} $message"
    else
        echo -e "${RED}✗${NC} $message"
    fi
}

# Function to run check
run_check() {
    local check_name=$1
    local command=$2
    local success_msg=$3
    local failure_msg=$4
    
    echo -e "\n${BLUE}Checking: $check_name${NC}"
    if eval "$command" &>/dev/null; then
        print_status "ok" "$success_msg"
        return 0
    else
        print_status "error" "$failure_msg"
        return 1
    fi
}

# 1. Check if deployment exists
echo -e "\n${BLUE}=== Deployment Status ===${NC}"
if kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" &>/dev/null; then
    print_status "ok" "Deployment '$DEPLOYMENT_NAME' found in namespace '$NAMESPACE'"
    
    # Get pod name
    POD_NAME=$(kubectl get pods -n "$NAMESPACE" -l app=java-app -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -n "$POD_NAME" ]; then
        print_status "ok" "Pod found: $POD_NAME"
    else
        print_status "error" "No running pod found for deployment"
        exit 1
    fi
else
    print_status "error" "Deployment '$DEPLOYMENT_NAME' not found in namespace '$NAMESPACE'"
    echo "Usage: $0 <namespace> <deployment-name>"
    exit 1
fi

# 2. Check JVM flags
echo -e "\n${BLUE}=== JVM Configuration ===${NC}"
JVM_FLAGS=$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -- sh -c 'ps aux | grep java | head -1' 2>/dev/null || true)

if echo "$JVM_FLAGS" | grep -q "Xjit:perfTool"; then
    print_status "ok" "OpenJ9 perfTool flag detected"
elif echo "$JVM_FLAGS" | grep -q "XX:+PreserveFramePointer"; then
    print_status "warning" "HotSpot flags detected (this script is for OpenJ9)"
else
    print_status "error" "No profiling flags detected (missing -Xjit:perfTool)"
    echo "   Add -Xjit:perfTool to JAVA_TOOL_OPTIONS or OPENJ9_JAVA_OPTIONS"
fi

# 3. Check Java process PID
echo -e "\n${BLUE}=== Java Process ===${NC}"
JAVA_PID=$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -- sh -c 'pgrep -f "java.*jar" | head -1' 2>/dev/null || true)

if [ -n "$JAVA_PID" ]; then
    print_status "ok" "Java process found (PID: $JAVA_PID)"
else
    print_status "error" "Java process not found"
    exit 1
fi

# 4. Check OpenJ9 version
echo -e "\n${BLUE}=== JVM Version ===${NC}"
JVM_VERSION=$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -- java -version 2>&1 || true)

if echo "$JVM_VERSION" | grep -q "OpenJ9"; then
    OPENJ9_VER=$(echo "$JVM_VERSION" | grep OpenJ9 | sed 's/.*openj9-//' | cut -d',' -f1)
    print_status "ok" "OpenJ9 detected (version: $OPENJ9_VER)"
    
    # Check version is adequate
    if echo "$OPENJ9_VER" | grep -qE "0\.(9|[1-9][0-9])\."; then
        print_status "ok" "OpenJ9 version supports perfTool"
    else
        print_status "warning" "OpenJ9 version may have limited perfTool support (< 0.9.0)"
    fi
elif echo "$JVM_VERSION" | grep -q "HotSpot"; then
    print_status "warning" "HotSpot JVM detected (this script is for OpenJ9)"
    echo "   For HotSpot, use perf-map-agent instead of -Xjit:perfTool"
else
    print_status "warning" "Could not determine JVM type"
fi

# 5. Check perf map file
echo -e "\n${BLUE}=== Perf Map Files ===${NC}"
PERF_MAP=$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -- sh -c "ls -lh /tmp/perf-${JAVA_PID}.map 2>/dev/null" || true)

if [ -n "$PERF_MAP" ]; then
    print_status "ok" "Perf map found: /tmp/perf-${JAVA_PID}.map"
    
    # Check file size
    FILE_SIZE=$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -- sh -c "wc -l /tmp/perf-${JAVA_PID}.map 2>/dev/null | awk '{print \$1}'" || echo "0")
    if [ "$FILE_SIZE" -gt 0 ]; then
        print_status "ok" "Perf map has $FILE_SIZE entries"
        
        # Show sample entries
        echo "   Sample entries:"
        kubectl exec -n "$NAMESPACE" "$POD_NAME" -- sh -c "head -3 /tmp/perf-${JAVA_PID}.map 2>/dev/null" | sed 's/^/     /'
    else
        print_status "warning" "Perf map is empty (JIT compilation may not have occurred yet)"
        echo "   Run some application load to trigger JIT compilation"
    fi
else
    print_status "error" "Perf map not found at /tmp/perf-${JAVA_PID}.map"
    echo ""
    echo "   Troubleshooting steps:"
    echo "   1. Ensure -Xjit:perfTool flag is set"
    echo "   2. Check /tmp is writable: kubectl exec -n $NAMESPACE $POD_NAME -- ls -ld /tmp"
    echo "   3. Restart pod to reload JVM with correct flags"
    echo "   4. Trigger hot code paths to force JIT compilation"
fi

# 6. Check /tmp permissions
echo -e "\n${BLUE}=== File Permissions ===${NC}"
TMP_PERMS=$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -- stat -c '%a' /tmp 2>/dev/null || true)

if [ "$TMP_PERMS" = "1777" ] || [ "$TMP_PERMS" = "777" ]; then
    print_status "ok" "/tmp has correct permissions ($TMP_PERMS)"
else
    print_status "warning" "/tmp permissions may be restrictive ($TMP_PERMS)"
fi

# 7. Check telegen agent
echo -e "\n${BLUE}=== Telegen Agent Status ===${NC}"
if kubectl get daemonset telegen-agent -n telegen-system &>/dev/null; then
    print_status "ok" "Telegen DaemonSet found"
    
    # Find telegen pod on same node
    NODE_NAME=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.nodeName}')
    TELEGEN_POD=$(kubectl get pods -n telegen-system -l app=telegen-agent \
        --field-selector spec.nodeName="$NODE_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    
    if [ -n "$TELEGEN_POD" ]; then
        print_status "ok" "Telegen agent found on same node: $TELEGEN_POD"
        
        # Check if telegen can see the perf map
        if kubectl exec -n telegen-system "$TELEGEN_POD" -- sh -c "ls /host/proc/${JAVA_PID}/root/tmp/perf-${JAVA_PID}.map" &>/dev/null; then
            print_status "ok" "Telegen can access perf map via namespace"
        else
            print_status "warning" "Telegen may not be able to access perf map"
            echo "   Check hostPID: true in DaemonSet spec"
        fi
    else
        print_status "warning" "No telegen agent found on node $NODE_NAME"
    fi
else
    print_status "warning" "Telegen DaemonSet not found in telegen-system namespace"
fi

# 8. Check SELinux (OpenShift specific)
echo -e "\n${BLUE}=== Security Context ===${NC}"
if command -v getenforce &> /dev/null; then
    if [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
        print_status "warning" "SELinux is enforcing - may need context adjustments"
        echo "   If perf maps aren't accessible, run:"
        echo "   chcon -t container_file_t /tmp/perf-*.map"
    else
        print_status "ok" "SELinux not enforcing"
    fi
fi

# 9. Test profiling data collection
echo -e "\n${BLUE}=== Profiling Test ===${NC}"
if [ -n "$TELEGEN_POD" ]; then
    echo "Testing symbol resolution..."
    
    # Try to get a sample stack from telegen logs
    RECENT_LOGS=$(kubectl logs -n telegen-system "$TELEGEN_POD" --tail=50 --since=1m 2>/dev/null | grep -i "java\|jit\|resolved" || true)
    
    if echo "$RECENT_LOGS" | grep -q "loaded JIT perf map"; then
        print_status "ok" "Telegen is loading JIT perf maps"
    else
        print_status "warning" "No recent JIT perf map activity in telegen logs"
    fi
    
    if echo "$RECENT_LOGS" | grep -q "resolved via JIT"; then
        print_status "ok" "Java methods are being resolved"
    else
        print_status "warning" "No resolved Java methods in recent logs"
        echo "   Enable debug logging: TELEGEN_DEBUG_LOGGING=true"
    fi
fi

# Summary
echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}Validation Summary${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo "Namespace: $NAMESPACE"
echo "Deployment: $DEPLOYMENT_NAME"
echo "Pod: $POD_NAME"
echo "Java PID: $JAVA_PID"
echo ""

if [ -n "$PERF_MAP" ] && [ "$FILE_SIZE" -gt 0 ]; then
    echo -e "${GREEN}✓ Profiling Configuration: READY${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Generate application load to trigger JIT compilation"
    echo "2. Check Grafana/Prometheus for profiling metrics"
    echo "3. Verify flame graphs show Java method names (not hex addresses)"
    echo ""
    echo "To view live profiling data:"
    echo "  kubectl port-forward -n telegen-system svc/telegen-api 8080:8080"
    echo "  curl http://localhost:8080/debug/pprof/profile?seconds=30 > profile.pb.gz"
    echo "  go tool pprof -http=:9090 profile.pb.gz"
else
    echo -e "${YELLOW}⚠ Profiling Configuration: INCOMPLETE${NC}"
    echo ""
    echo "Required actions:"
    echo "1. Add -Xjit:perfTool to JVM options"
    echo "2. Restart pod: kubectl rollout restart deployment/$DEPLOYMENT_NAME -n $NAMESPACE"
    echo "3. Wait for application warmup and JIT compilation"
    echo "4. Re-run this validation script"
    echo ""
    echo "Documentation: docs/java-openj9-profiling.md"
fi

echo ""
