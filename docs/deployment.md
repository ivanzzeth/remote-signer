# Deployment Architecture

## Overview

Remote-Signer is designed to be deployed as a stateless service with a SQL database as the backing store. Two deployment options are supported:

| Option | Description |
|--------|-------------|
| **Direct build** | Compile the Go binary and run on the host (e.g. `./scripts/deploy.sh local-run` or `./remote-signer`). Use SQLite (file DSN) or PostgreSQL. |
| **Docker** | Run with Docker Compose; includes PostgreSQL. Suited for production. |

See the main [README](../README.md#deployment) for quick commands. This document covers deployment configurations and considerations in detail.

## Deployment Diagram

```
                    ┌─────────────────────────────────────────┐
                    │            Load Balancer                 │
                    │         (TLS termination)                │
                    └──────────────────┬──────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
    │  Remote-Signer   │    │  Remote-Signer   │    │  Remote-Signer   │
    │    Instance 1    │    │    Instance 2    │    │    Instance 3    │
    │    (Port 8548)   │    │    (Port 8548)   │    │    (Port 8548)   │
    └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
             │                       │                       │
             └───────────────────────┼───────────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │     PostgreSQL      │
                          │   (Primary + HA)    │
                          └─────────────────────┘

    ┌──────────────────────────────────────────────────────────────────┐
    │                        External Services                          │
    │  ┌───────────┐    ┌───────────┐    ┌───────────────────────────┐ │
    │  │   Slack   │    │ Pushover  │    │     EVM RPC Nodes         │ │
    │  │  (notify) │    │ (notify)  │    │ (optional, for validation)│ │
    │  └───────────┘    └───────────┘    └───────────────────────────┘ │
    └──────────────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_DSN` | Database DSN (PostgreSQL or SQLite file DSN). When set, it overrides `database.dsn` in config (useful for Docker). | No (but recommended for Docker) |

Config file path is set by the `-config` flag (default: `config.yaml`), not by environment.

### Configuration File

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8548

database:
  dsn: "${DATABASE_DSN}"   # or "file:./data/signer.db" for SQLite
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m

security:
  max_request_age: 60s     # request timestamp must be within this window
  rate_limit_default: 100  # per-minute default for API keys that omit rate_limit
  ip_whitelist:
    enabled: true
    allowed_ips:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
    # trust_proxy: false   # set true only behind a trusted reverse proxy

chains:
  evm:
    enabled: true
    signers:
      private_keys:
        - address: "0x..."
          key_env: "EVM_SIGNER_KEY_1"   # env var with hex private key (no 0x prefix)
          enabled: true
      # keystores:
      #   - address: "0x..."
      #     path: "/secrets/keystore.json"
      #     password_env: "KEYSTORE_PASSWORD"
      #     enabled: true
    foundry:
      enabled: true
      forge_path: ""
      cache_dir: "./data/forge-cache"
      timeout: "30s"

api_keys:
  - id: "client-1"
    name: "Production Client"
    public_key: "MCowBQYDK2VwAyEA..."   # Ed25519 public key (base64 or hex)
    enabled: true
    rate_limit: 100                      # requests per minute
    # allowed_chain_types: []            # empty = all
    # allowed_signers: []                 # empty = all
    # allowed_hd_wallets: []             # HD wallet primary addresses (empty = none)

notify:
  slack:
    enabled: false
    bot_token: "${SLACK_BOT_TOKEN}"
  pushover:
    enabled: false
    app_token: "${PUSHOVER_APP_TOKEN}"

logger:
  level: "info"
  pretty: false
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /remote-signer ./cmd/remote-signer

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /remote-signer /usr/local/bin/

EXPOSE 8548

ENTRYPOINT ["remote-signer"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  remote-signer:
    image: remote-signer:latest
    ports:
      - "8548:8548"
    environment:
      - DATABASE_DSN=postgres://user:pass@db:5432/signer?sslmode=disable
      - KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD}
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
    volumes:
      - ./config.yaml:/etc/remote-signer/config.yaml:ro
      - ./secrets:/secrets:ro
    depends_on:
      - db

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=signer
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

## Kubernetes Deployment

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: remote-signer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: remote-signer
  template:
    metadata:
      labels:
        app: remote-signer
    spec:
      containers:
        - name: remote-signer
          image: remote-signer:latest
          ports:
            - containerPort: 8548
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: remote-signer-secrets
                  key: database-url
            - name: KEYSTORE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: remote-signer-secrets
                  key: keystore-password
          volumeMounts:
            - name: config
              mountPath: /etc/remote-signer
              readOnly: true
            - name: keystore
              mountPath: /secrets
              readOnly: true
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /health
              port: 8548
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: 8548
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: config
          configMap:
            name: remote-signer-config
        - name: keystore
          secret:
            secretName: remote-signer-keystore
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: remote-signer
spec:
  selector:
    app: remote-signer
  ports:
    - port: 8548
      targetPort: 8548
  type: ClusterIP
```

### Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: remote-signer
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - signer.example.com
      secretName: signer-tls
  rules:
    - host: signer.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: remote-signer
                port:
                  number: 8548
```

## Security Considerations

### Network Security

1. **TLS Termination**: Use a reverse proxy (nginx, HAProxy) or load balancer for TLS
2. **IP Whitelist**: Configure allowed client IPs in `security.ip_whitelist`
3. **Network Isolation**: Deploy in private subnet, expose only via load balancer

### Secret Management

| Secret | Storage Recommendation |
|--------|----------------------|
| Keystore files | Kubernetes Secrets, HashiCorp Vault |
| Keystore passwords | Environment variables from secret store |
| Private keys | HSM or secure secret manager |
| API key private keys | Client-side only, never stored on server |
| Database credentials | Secret manager with rotation |

### Key Storage Options

```
┌─────────────────────────────────────────────────────────────────┐
│                     Security Levels                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Level 1: Environment Variable (Basic)                          │
│  ├─ Private key in SIGNER_PRIVATE_KEY env var                   │
│  └─ Suitable for: development, testing                          │
│                                                                  │
│  Level 2: Encrypted Keystore (Standard)                         │
│  ├─ JSON keystore file + password                               │
│  ├─ Password from env var or secret manager                     │
│  └─ Suitable for: staging, low-value production                 │
│                                                                  │
│  Level 3: Secret Manager (Recommended)                          │
│  ├─ Keys stored in HashiCorp Vault, AWS KMS, etc.               │
│  ├─ Dynamic credential retrieval                                │
│  └─ Suitable for: production                                    │
│                                                                  │
│  Level 4: HSM (Enterprise)                                      │
│  ├─ Hardware Security Module integration                        │
│  ├─ Keys never leave HSM                                        │
│  └─ Suitable for: high-value production, compliance             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## High Availability

### Database HA

- Use PostgreSQL with streaming replication
- Configure connection pooling (PgBouncer)
- Set appropriate timeouts and retries

### Service HA

- Run multiple instances behind load balancer
- Stateless design allows horizontal scaling
- No sticky sessions required

### Failover Strategy

```
Primary Instance          Secondary Instances
       │                         │
       ▼                         ▼
┌─────────────┐          ┌─────────────┐
│  Write DB   │◀────────▶│ Read Replica│
│  (Primary)  │ streaming│ (Standby)   │
└─────────────┘ replica  └─────────────┘
```

## Monitoring

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (use for both liveness and readiness probes) |

### Metrics (Prometheus format)

```
# Request metrics
remote_signer_requests_total{status="completed"} 1234
remote_signer_requests_total{status="rejected"} 56
remote_signer_request_duration_seconds{quantile="0.99"} 0.15

# Rule metrics
remote_signer_rule_evaluations_total{result="matched"} 1000
remote_signer_rule_evaluations_total{result="blocked"} 50

# Auth metrics
remote_signer_auth_attempts_total{result="success"} 5000
remote_signer_auth_attempts_total{result="failure"} 10
```

### Logging

JSON structured logging with fields:
- `level`: Log level
- `timestamp`: ISO8601 timestamp
- `request_id`: Request correlation ID
- `component`: Source component
- `message`: Log message
- `error`: Error details (if applicable)

## Backup & Recovery

### Database Backup

```bash
# Daily backup
pg_dump -h localhost -U user -d signer > backup_$(date +%Y%m%d).sql

# Point-in-time recovery with WAL archiving
archive_mode = on
archive_command = 'cp %p /backup/wal/%f'
```

### Key Backup

- Keystore files: Encrypted backup to secure storage
- Recovery procedure: Restore keystore + password to new instance
- Test recovery process regularly

## Capacity Planning

### Resource Estimates

| Load | CPU | Memory | DB Connections |
|------|-----|--------|----------------|
| 10 req/s | 0.5 core | 256MB | 5 |
| 100 req/s | 2 cores | 512MB | 20 |
| 1000 req/s | 8 cores | 2GB | 50 |

### Scaling Guidelines

1. **Horizontal**: Add more instances for request throughput
2. **Vertical**: Increase resources for complex rule evaluation (Solidity)
3. **Database**: Scale read replicas, consider sharding for > 10M records
