# Kubernetes Installation

Deploy Telegen on Kubernetes using kubectl manifests.

## Prerequisites

- Kubernetes 1.21+
- kubectl configured with cluster access
- Nodes running Linux 4.18+ kernel
- Cluster admin permissions (for RBAC)

---

## Agent Mode (DaemonSet)

Agent mode deploys Telegen on every node for local eBPF instrumentation.

### Step 1: Create Namespace

```bash
kubectl create namespace telegen
```

### Step 2: Apply RBAC

```bash
kubectl apply -f - <<EOF
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
  - apiGroups: [""]
    resources: ["nodes/proxy"]
    verbs: ["get"]
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

### Step 3: Create ConfigMap

```bash
kubectl apply -f - <<EOF
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
        interval: 30s
EOF
```

### Step 4: Deploy DaemonSet

```bash
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: telegen
  namespace: telegen
  labels:
    app.kubernetes.io/name: telegen
    app.kubernetes.io/component: agent
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: telegen
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        app.kubernetes.io/name: telegen
        app.kubernetes.io/component: agent
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "19090"
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
      
      containers:
        - name: telegen
          image: ghcr.io/platformbuilds/telegen:latest
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
                - SYS_RESOURCE
                - NET_ADMIN
                - NET_RAW
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
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          
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

### Step 5: Create Service

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: telegen
  namespace: telegen
  labels:
    app.kubernetes.io/name: telegen
spec:
  type: ClusterIP
  clusterIP: None
  selector:
    app.kubernetes.io/name: telegen
  ports:
    - name: metrics
      port: 19090
      targetPort: metrics
    - name: health
      port: 8080
      targetPort: health
EOF
```

---

## Collector Mode (Deployment)

Collector mode deploys Telegen for remote device monitoring (SNMP, storage arrays).

### Create Secrets

```bash
kubectl create secret generic telegen-secrets \
  --namespace telegen \
  --from-literal=dell-password='your-password' \
  --from-literal=pure-token='your-api-token' \
  --from-literal=snmp-auth-password='your-snmp-password'
```

### Deploy Collector

```bash
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: telegen-collector
  namespace: telegen
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: telegen-collector
  template:
    metadata:
      labels:
        app.kubernetes.io/name: telegen-collector
    spec:
      serviceAccountName: telegen
      
      containers:
        - name: telegen
          image: ghcr.io/platformbuilds/telegen:latest
          args:
            - "--mode=collector"
            - "--config=/etc/telegen/collector.yaml"
          
          ports:
            - name: snmp-traps
              containerPort: 162
              protocol: UDP
            - name: metrics
              containerPort: 19090
            - name: health
              containerPort: 8080
          
          env:
            - name: DELL_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: telegen-secrets
                  key: dell-password
          
          volumeMounts:
            - name: config
              mountPath: /etc/telegen
          
          resources:
            requests:
              cpu: 200m
              memory: 512Mi
            limits:
              cpu: 2000m
              memory: 2Gi
          
          livenessProbe:
            httpGet:
              path: /healthz
              port: health
            initialDelaySeconds: 10
      
      volumes:
        - name: config
          configMap:
            name: telegen-collector-config
---
apiVersion: v1
kind: Service
metadata:
  name: telegen-collector
  namespace: telegen
spec:
  selector:
    app.kubernetes.io/name: telegen-collector
  ports:
    - name: snmp-traps
      port: 162
      targetPort: 162
      protocol: UDP
    - name: metrics
      port: 19090
EOF
```

---

## Verification

### Check Pod Status

```bash
kubectl get pods -n telegen -o wide
```

Expected output:
```
NAME            READY   STATUS    RESTARTS   AGE   IP           NODE
telegen-abc12   1/1     Running   0          5m    10.0.1.10    node-1
telegen-def34   1/1     Running   0          5m    10.0.1.11    node-2
telegen-ghi56   1/1     Running   0          5m    10.0.1.12    node-3
```

### Check Logs

```bash
kubectl logs -n telegen -l app.kubernetes.io/name=telegen --tail=50
```

### Check Metrics

```bash
kubectl port-forward -n telegen daemonset/telegen 19090:19090 &
curl http://localhost:19090/metrics | grep telegen
```

---

## Troubleshooting

### Pod Not Starting

```bash
# Check events
kubectl describe pod -n telegen -l app.kubernetes.io/name=telegen

# Common issues:
# - Missing privileges: ensure privileged: true
# - BTF not available: check kernel version >= 5.8
# - BPF filesystem not mounted: check /sys/fs/bpf
```

### Permission Denied Errors

Ensure the DaemonSet has:
- `hostPID: true`
- `hostNetwork: true`
- `privileged: true` security context
- Required capabilities (SYS_ADMIN, BPF, etc.)

### No Telemetry Arriving

```bash
# Check OTLP endpoint connectivity
kubectl exec -n telegen -it $(kubectl get pod -n telegen -l app.kubernetes.io/name=telegen -o jsonpath='{.items[0].metadata.name}') -- \
  wget -q -O- http://otel-collector.observability:4317/health
```

---

## Next Steps

- {doc}`helm` - Simplified deployment with Helm
- {doc}`../configuration/agent-mode` - Agent configuration options
