# ESXi MCP Server - Docker Guide

This guide provides instructions for running the ESXi MCP Server using Docker and Docker Compose.

## Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Access to a VMware vCenter Server or ESXi host

### 1. Setup

```bash
# Clone the repository
git clone <repository-url>
cd esxi-mcp-server

# Create necessary directories and configuration
make setup

# Create environment variables file (optional)
make env-example
cp .env.example .env
```

### 2. Configuration

You have two options for configuration:

#### Option A: Configuration File (Recommended)

Edit `config/config.yaml`:

```yaml
vcenter_host: "your-vcenter-ip"
vcenter_user: "administrator@vsphere.local"
vcenter_password: "your-password"
datacenter: "your-datacenter"
cluster: "your-cluster"
datastore: "your-datastore"
network: "VM Network"
insecure: true
api_key: "your-api-key"
log_level: "INFO"
```

#### Option B: Environment Variables

Edit `.env` file:

```bash
VCENTER_HOST=your-vcenter-ip
VCENTER_USER=administrator@vsphere.local
VCENTER_PASSWORD=your-password
VCENTER_DATACENTER=your-datacenter
VCENTER_CLUSTER=your-cluster
VCENTER_DATASTORE=your-datastore
VCENTER_NETWORK=VM Network
VCENTER_INSECURE=true
MCP_API_KEY=your-api-key
MCP_LOG_LEVEL=INFO
```

### 3. Run the Server

```bash
# Build and run
make dev

# Or run in background
make run

# Check status
make status

# View logs
make logs
```

## Available Commands

Use `make help` to see all available commands:

```bash
make help
```

### Build Commands

- `make build` - Build Docker image
- `make build-no-cache` - Build without cache

### Run Commands

- `make run` - Run in background
- `make run-logs` - Run with logs
- `make stop` - Stop containers
- `make restart` - Restart containers

### Development Commands

- `make dev` - Development mode (build + run with logs)
- `make logs` - Show logs
- `make shell` - Open bash shell in container
- `make status` - Show container status
- `make health` - Check container health

### Maintenance Commands

- `make clean` - Remove containers and volumes
- `make clean-all` - Remove everything
- `make update` - Rebuild and restart

## Docker Architecture

### Multi-stage Build

The Dockerfile uses a multi-stage build process:

1. **Builder Stage**: Installs build dependencies and Python packages
2. **Production Stage**: Creates a minimal runtime image

### Security Features

- Runs as non-root user (`mcpuser`)
- Minimal base image (python:3.11-slim)
- Only necessary runtime dependencies
- Configurable resource limits

### Directory Structure

```
/app/
├── server.py              # Main application
├── config.yaml.sample     # Configuration template
├── docker-entrypoint.sh   # Startup script
├── config/                # Configuration directory (mounted)
│   └── config.yaml        # Runtime configuration
└── logs/                  # Log directory (mounted)
    └── vmware_mcp.log     # Application logs
```

## Configuration Options

### Volume Mounts

- `./config.yaml:/app/config/config.yaml:ro` - Configuration file (read-only)
- `./logs:/app/logs` - Log directory

### Environment Variables

All configuration options can be set via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `VCENTER_HOST` | vCenter/ESXi hostname | Required |
| `VCENTER_USER` | Username | Required |
| `VCENTER_PASSWORD` | Password | Required |
| `VCENTER_DATACENTER` | Datacenter name | Auto-detect |
| `VCENTER_CLUSTER` | Cluster name | Auto-detect |
| `VCENTER_DATASTORE` | Datastore name | Auto-detect |
| `VCENTER_NETWORK` | Network name | VM Network |
| `VCENTER_INSECURE` | Skip SSL verification | true |
| `MCP_API_KEY` | API authentication key | None |
| `MCP_LOG_LEVEL` | Log level | INFO |

### Resource Limits

Default resource limits in docker-compose.yml:

- **Memory**: 512MB limit, 256MB reserved
- **CPU**: 0.5 cores limit, 0.25 cores reserved

## Health Checks

The container includes automatic health checks:

- **Interval**: 30 seconds
- **Timeout**: 10 seconds
- **Retries**: 3
- **Start Period**: 40 seconds

Check health manually:

```bash
make health
```

## Networking

The server exposes:

- **Port 8080**: HTTP API endpoint
- **Path `/sse`**: Server-Sent Events endpoint
- **Path `/sse/messages`**: JSON-RPC messages endpoint

## Troubleshooting

### Check Logs

```bash
make logs
```

### Check Container Status

```bash
make status
```

### Open Shell in Container

```bash
make shell
```

### Common Issues

1. **Configuration not found**: Ensure `config/config.yaml` exists or environment variables are set
2. **Permission denied**: Check that the `logs` directory is writable
3. **Connection failed**: Verify vCenter/ESXi connectivity and credentials
4. **Health check failed**: Check if the server is responding on port 8080

### Debug Mode

Run with debug logging:

```bash
# Set in .env file
MCP_LOG_LEVEL=DEBUG

# Or in config.yaml
log_level: "DEBUG"
```

## Production Deployment

### Security Recommendations

1. Use a dedicated user account for vCenter access
2. Enable API key authentication
3. Use valid SSL certificates (set `insecure: false`)
4. Limit container resources
5. Use Docker secrets for sensitive data

### High Availability

For production deployments, consider:

- Running multiple container instances
- Using a load balancer
- Implementing persistent storage for logs
- Setting up monitoring and alerting

## Examples

### Basic Usage

```bash
# Start the server
make run

# Check if it's working
curl http://localhost:8080/sse
```

### API Authentication

```bash
# With API key
curl -H "Authorization: Bearer your-api-key" http://localhost:8080/sse
```

### Development

```bash
# Development workflow
make build
make dev

# Make changes to code
# Rebuild and restart
make update
``` 