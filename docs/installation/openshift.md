# OpenShift Installation

Deploy Telegen on Red Hat OpenShift with the required Security Context Constraints.

## Prerequisites

- OpenShift 4.10+
- Cluster admin permissions
- `oc` CLI configured

---

## Step 1: Create Project

```bash
oc new-project telegen
```

---

## Step 2: Create Security Context Constraints

Telegen requires privileged access for eBPF instrumentation:

```bash
oc apply -f - <<EOF
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: telegen-scc
allowPrivilegedContainer: true
allowHostPID: true
allowHostNetwork: true
allowHostPorts: true
allowHostDirVolumePlugin: true
allowedCapabilities:
  - SYS_ADMIN
  - SYS_PTRACE
  - SYS_RESOURCE
  - NET_ADMIN
  - NET_RAW
  - BPF
  - PERFMON
  - DAC_READ_SEARCH
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: RunAsAny
fsGroup:
  type: RunAsAny
supplementalGroups:
  type: RunAsAny
volumes:
  - configMap
  - emptyDir
  - hostPath
  - secret
users:
  - system:serviceaccount:telegen:telegen
priority: 10
EOF
```

---

## Step 3: Create Service Account and RBAC

```bash
oc apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: telegen
  namespace: telegen
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: telegen
rules:
  - apiGroups: [""]
    resources: ["nodes", "pods", "services", "endpoints", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["security.openshift.io"]
    resources: ["securitycontextconstraints"]
    resourceNames: ["telegen-scc"]
    verbs: ["use"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: telegen
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: telegen
subjects:
  - kind: ServiceAccount
    name: telegen
    namespace: telegen
EOF
```

---

## Step 4: Create ConfigMap

```bash
oc apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: telegen-config
  namespace: telegen
data:
  config.yaml: |
    telegen:
      mode: agent
      service_name: telegen
      log_level: info
    
    otlp:
      endpoint: "otel-collector.observability:4317"
      protocol: grpc
      insecure: true
    
    agent:
      ebpf:
        enabled: true
        network: true
        syscalls: true
      profiling:
        enabled: true
        cpu: true
        memory: true
      discovery:
        enabled: true
      security:
        enabled: true
EOF
```

---

## Step 5: Deploy DaemonSet

```bash
oc apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: telegen
  namespace: telegen
  labels:
    app: telegen
spec:
  selector:
    matchLabels:
      app: telegen
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        app: telegen
      annotations:
        openshift.io/scc: telegen-scc
    spec:
      serviceAccountName: telegen
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      priorityClassName: system-node-critical
      
      tolerations:
        - operator: Exists
          effect: NoSchedule
        - operator: Exists
          effect: NoExecute
        - key: node-role.kubernetes.io/master
          operator: Exists
          effect: NoSchedule
        - key: node-role.kubernetes.io/infra
          operator: Exists
          effect: NoSchedule
      
      containers:
        - name: telegen
          image: ghcr.io/mirastacklabs-ai/telegen:latest
          args:
            - "--config=/etc/telegen/config.yaml"
            - "--mode=agent"
          
          securityContext:
            privileged: true
            runAsUser: 0
            capabilities:
              add:
                - SYS_ADMIN
                - SYS_PTRACE
                - NET_ADMIN
                - BPF
                - PERFMON
          
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 1Gi
          
          ports:
            - name: metrics
              containerPort: 19090
            - name: health
              containerPort: 8080
          
          livenessProbe:
            httpGet:
              path: /healthz
              port: health
            initialDelaySeconds: 10
            periodSeconds: 30
          
          readinessProbe:
            httpGet:
              path: /readyz
              port: health
            initialDelaySeconds: 5
            periodSeconds: 10
          
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          
          volumeMounts:
            - name: config
              mountPath: /etc/telegen
            - name: sys
              mountPath: /sys
              readOnly: true
            - name: proc
              mountPath: /host/proc
              readOnly: true
            - name: debugfs
              mountPath: /sys/kernel/debug
            - name: bpf
              mountPath: /sys/fs/bpf
      
      volumes:
        - name: config
          configMap:
            name: telegen-config
        - name: sys
          hostPath:
            path: /sys
        - name: proc
          hostPath:
            path: /proc
        - name: debugfs
          hostPath:
            path: /sys/kernel/debug
        - name: bpf
          hostPath:
            path: /sys/fs/bpf
EOF
```

---

## Step 6: Create Service

```bash
oc apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: telegen
  namespace: telegen
  labels:
    app: telegen
spec:
  clusterIP: None
  selector:
    app: telegen
  ports:
    - name: metrics
      port: 19090
    - name: health
      port: 8080
EOF
```

---

## Verification

### Check Pods

```bash
oc get pods -n telegen -o wide
```

### Check SCC Assignment

```bash
oc get pods -n telegen -o yaml | grep -A 5 "openshift.io/scc"
```

### Check Logs

```bash
oc logs -n telegen -l app=telegen --tail=50
```

### Check Metrics

```bash
oc port-forward -n telegen daemonset/telegen 19090:19090 &
curl http://localhost:19090/metrics | grep telegen
```

---

## OpenShift-Specific Considerations

### SELinux

Telegen runs with `RunAsAny` SELinux context. If you need stricter controls:

```yaml
seLinuxContext:
  type: MustRunAs
  seLinuxOptions:
    type: spc_t  # Super Privileged Container
```

### Node Selectors

To run only on worker nodes:

```yaml
nodeSelector:
  node-role.kubernetes.io/worker: ""
```

### Resource Quotas

If your project has resource quotas, ensure they accommodate Telegen:

```bash
oc describe quota -n telegen
```

---

## Monitoring with OpenShift Monitoring

### Create ServiceMonitor

```bash
oc apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: telegen
  namespace: telegen
  labels:
    app: telegen
spec:
  selector:
    matchLabels:
      app: telegen
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
EOF
```

### Enable User Workload Monitoring

```bash
oc apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    enableUserWorkload: true
EOF
```

---

## Troubleshooting

### SCC Issues

```bash
# Check which SCC is being used
oc get pods -n telegen -o yaml | grep "openshift.io/scc"

# Verify SCC permissions
oc adm policy who-can use scc telegen-scc
```

### Pod Not Scheduling

```bash
# Check events
oc get events -n telegen --sort-by='.lastTimestamp'

# Describe pod
oc describe pod -n telegen -l app=telegen
```

### Permission Denied

Ensure the ServiceAccount is bound to the SCC:

```bash
oc adm policy add-scc-to-user telegen-scc -z telegen -n telegen
```

---

## Next Steps

- {doc}`../configuration/index` - Configuration reference
- {doc}`../features/index` - Feature guides
