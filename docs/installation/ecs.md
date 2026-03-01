# AWS ECS Installation

Deploy Telegen on Amazon Elastic Container Service (ECS).

## Prerequisites

- AWS CLI configured
- ECS cluster (EC2 launch type)
- IAM permissions for ECS task creation
- EC2 instances with Linux kernel 4.18+

```{note}
Telegen requires EC2 launch type due to eBPF requirements. Fargate is not supported.
```

---

## Agent Mode (Daemon Service)

### Step 1: Create IAM Role

```bash
# Create trust policy
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create role
aws iam create-role \
  --role-name telegen-task-role \
  --assume-role-policy-document file://trust-policy.json

# Attach policies
aws iam attach-role-policy \
  --role-name telegen-task-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

aws iam attach-role-policy \
  --role-name telegen-task-role \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess
```

### Step 2: Create Task Definition

```bash
cat > telegen-task-definition.json <<EOF
{
  "family": "telegen-agent",
  "networkMode": "host",
  "pidMode": "host",
  "requiresCompatibilities": ["EC2"],
  "executionRoleArn": "arn:aws:iam::YOUR_ACCOUNT_ID:role/telegen-task-role",
  "taskRoleArn": "arn:aws:iam::YOUR_ACCOUNT_ID:role/telegen-task-role",
  "containerDefinitions": [
    {
      "name": "telegen-agent",
      "image": "ghcr.io/mirastacklabs-ai/telegen:latest",
      "essential": true,
      "privileged": true,
      "command": ["--mode=agent", "--config=/etc/telegen/config.yaml"],
      "environment": [
        {
          "name": "TELEGEN_OTLP_ENDPOINT",
          "value": "otel-collector.internal:4317"
        },
        {
          "name": "TELEGEN_LOG_LEVEL",
          "value": "info"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "sys",
          "containerPath": "/sys",
          "readOnly": true
        },
        {
          "sourceVolume": "proc",
          "containerPath": "/host/proc",
          "readOnly": true
        },
        {
          "sourceVolume": "debugfs",
          "containerPath": "/sys/kernel/debug",
          "readOnly": false
        },
        {
          "sourceVolume": "bpf",
          "containerPath": "/sys/fs/bpf",
          "readOnly": false
        }
      ],
      "portMappings": [
        {
          "containerPort": 19090,
          "hostPort": 19090,
          "protocol": "tcp"
        },
        {
          "containerPort": 8080,
          "hostPort": 8080,
          "protocol": "tcp"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q -O- http://localhost:8080/healthz || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 10
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/telegen",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "telegen"
        }
      },
      "cpu": 256,
      "memory": 512,
      "memoryReservation": 256
    }
  ],
  "volumes": [
    {
      "name": "sys",
      "host": {
        "sourcePath": "/sys"
      }
    },
    {
      "name": "proc",
      "host": {
        "sourcePath": "/proc"
      }
    },
    {
      "name": "debugfs",
      "host": {
        "sourcePath": "/sys/kernel/debug"
      }
    },
    {
      "name": "bpf",
      "host": {
        "sourcePath": "/sys/fs/bpf"
      }
    }
  ]
}
EOF

# Register task definition
aws ecs register-task-definition --cli-input-json file://telegen-task-definition.json
```

### Step 3: Create CloudWatch Log Group

```bash
aws logs create-log-group --log-group-name /ecs/telegen
```

### Step 4: Create Daemon Service

```bash
cat > telegen-service.json <<EOF
{
  "cluster": "your-cluster-name",
  "serviceName": "telegen-agent",
  "taskDefinition": "telegen-agent",
  "schedulingStrategy": "DAEMON",
  "deploymentConfiguration": {
    "maximumPercent": 100,
    "minimumHealthyPercent": 0
  },
  "placementConstraints": [],
  "enableECSManagedTags": true,
  "tags": [
    {
      "key": "Service",
      "value": "telegen"
    }
  ]
}
EOF

aws ecs create-service --cli-input-json file://telegen-service.json
```

---

## Collector Mode

For SNMP and storage array monitoring:

### Task Definition

```bash
cat > telegen-collector-task.json <<EOF
{
  "family": "telegen-collector",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["EC2", "FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::YOUR_ACCOUNT_ID:role/telegen-task-role",
  "taskRoleArn": "arn:aws:iam::YOUR_ACCOUNT_ID:role/telegen-task-role",
  "containerDefinitions": [
    {
      "name": "telegen-collector",
      "image": "ghcr.io/mirastacklabs-ai/telegen:latest",
      "essential": true,
      "command": ["--mode=collector", "--config=/etc/telegen/config.yaml"],
      "environment": [
        {
          "name": "TELEGEN_OTLP_ENDPOINT",
          "value": "otel-collector.internal:4317"
        }
      ],
      "secrets": [
        {
          "name": "DELL_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT_ID:secret:telegen/dell-password"
        },
        {
          "name": "SNMP_AUTH_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT_ID:secret:telegen/snmp-auth"
        }
      ],
      "portMappings": [
        {
          "containerPort": 162,
          "protocol": "udp"
        },
        {
          "containerPort": 19090,
          "protocol": "tcp"
        },
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q -O- http://localhost:8080/healthz || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/telegen-collector",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "telegen"
        }
      }
    }
  ]
}
EOF

aws ecs register-task-definition --cli-input-json file://telegen-collector-task.json
```

### Create Secrets

```bash
# Create secrets in Secrets Manager
aws secretsmanager create-secret \
  --name telegen/dell-password \
  --secret-string "your-dell-password"

aws secretsmanager create-secret \
  --name telegen/snmp-auth \
  --secret-string "your-snmp-password"
```

### Create Service

```bash
aws ecs create-service \
  --cluster your-cluster-name \
  --service-name telegen-collector \
  --task-definition telegen-collector \
  --desired-count 2 \
  --launch-type EC2 \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx]}"
```

---

## Using SSM Parameter Store

Alternative to Secrets Manager:

```bash
# Create parameters
aws ssm put-parameter \
  --name "/telegen/otlp-endpoint" \
  --value "otel-collector:4317" \
  --type String

aws ssm put-parameter \
  --name "/telegen/dell-password" \
  --value "your-password" \
  --type SecureString
```

Update task definition to use SSM:

```json
{
  "secrets": [
    {
      "name": "DELL_PASSWORD",
      "valueFrom": "arn:aws:ssm:us-east-1:YOUR_ACCOUNT_ID:parameter/telegen/dell-password"
    }
  ]
}
```

---

## IAM Policies

### Secrets Manager Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT_ID:secret:telegen/*"
      ]
    }
  ]
}
```

### SSM Parameter Store Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameters",
        "ssm:GetParameter"
      ],
      "Resource": [
        "arn:aws:ssm:us-east-1:YOUR_ACCOUNT_ID:parameter/telegen/*"
      ]
    }
  ]
}
```

---

## Verification

### Check Service Status

```bash
aws ecs describe-services \
  --cluster your-cluster-name \
  --services telegen-agent
```

### Check Tasks

```bash
aws ecs list-tasks \
  --cluster your-cluster-name \
  --service-name telegen-agent
```

### Check Logs

```bash
aws logs tail /ecs/telegen --follow
```

---

## Terraform Example

```hcl
resource "aws_ecs_task_definition" "telegen" {
  family                   = "telegen-agent"
  network_mode             = "host"
  pid_mode                 = "host"
  requires_compatibilities = ["EC2"]
  execution_role_arn       = aws_iam_role.telegen_execution.arn
  task_role_arn            = aws_iam_role.telegen_task.arn

  container_definitions = jsonencode([
    {
      name       = "telegen-agent"
      image      = "ghcr.io/mirastacklabs-ai/telegen:latest"
      essential  = true
      privileged = true
      command    = ["--mode=agent"]
      
      environment = [
        {
          name  = "TELEGEN_OTLP_ENDPOINT"
          value = var.otlp_endpoint
        }
      ]
      
      mountPoints = [
        {
          sourceVolume  = "sys"
          containerPath = "/sys"
          readOnly      = true
        },
        {
          sourceVolume  = "proc"
          containerPath = "/host/proc"
          readOnly      = true
        },
        {
          sourceVolume  = "debugfs"
          containerPath = "/sys/kernel/debug"
        },
        {
          sourceVolume  = "bpf"
          containerPath = "/sys/fs/bpf"
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.telegen.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "telegen"
        }
      }
    }
  ])

  volume {
    name      = "sys"
    host_path = "/sys"
  }

  volume {
    name      = "proc"
    host_path = "/proc"
  }

  volume {
    name      = "debugfs"
    host_path = "/sys/kernel/debug"
  }

  volume {
    name      = "bpf"
    host_path = "/sys/fs/bpf"
  }
}

resource "aws_ecs_service" "telegen" {
  name                = "telegen-agent"
  cluster             = aws_ecs_cluster.main.id
  task_definition     = aws_ecs_task_definition.telegen.arn
  scheduling_strategy = "DAEMON"
}
```

---

## Troubleshooting

### Task Not Starting

```bash
# Check stopped tasks
aws ecs list-tasks --cluster your-cluster --desired-status STOPPED

# Describe task
aws ecs describe-tasks --cluster your-cluster --tasks TASK_ARN
```

### Permission Issues

- Ensure EC2 instances have the ECS agent with correct permissions
- Verify IAM roles have necessary policies
- Check security groups allow outbound traffic to OTLP endpoint

### eBPF Errors

- ECS instances must be EC2 (not Fargate)
- Kernel must be 4.18+ (5.8+ recommended)
- Instance must have `/sys/fs/bpf` mounted

---

## Next Steps

- {doc}`../configuration/index` - Configuration reference
- {doc}`../features/index` - Feature guides
