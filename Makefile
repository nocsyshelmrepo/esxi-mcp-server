# ESXi MCP Server Makefile
# Provides convenient commands for Docker operations

# Variables
DOCKER_IMAGE = esxi-mcp-server
DOCKER_TAG = latest
CONTAINER_NAME = esxi-mcp-server
COMPOSE_FILE = docker-compose.yml

# Default target
.PHONY: help
help: ## Show this help message
	@echo "ESXi MCP Server Docker Commands"
	@echo "================================"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build commands
.PHONY: build
build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: build-no-cache
build-no-cache: ## Build Docker image without cache
	docker build --no-cache -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Run commands
.PHONY: run
run: ## Run container with docker-compose
	docker-compose -f $(COMPOSE_FILE) up -d

.PHONY: run-logs
run-logs: ## Run container with docker-compose and show logs
	docker-compose -f $(COMPOSE_FILE) up

.PHONY: stop
stop: ## Stop running containers
	docker-compose -f $(COMPOSE_FILE) down

.PHONY: restart
restart: ## Restart containers
	docker-compose -f $(COMPOSE_FILE) restart

# Development commands
.PHONY: logs
logs: ## Show container logs
	docker-compose -f $(COMPOSE_FILE) logs -f

.PHONY: shell
shell: ## Open bash shell in running container
	docker exec -it $(CONTAINER_NAME) bash

.PHONY: status
status: ## Show container status
	docker-compose -f $(COMPOSE_FILE) ps

# Maintenance commands
.PHONY: clean
clean: ## Remove containers and volumes
	docker-compose -f $(COMPOSE_FILE) down -v
	docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true

.PHONY: clean-all
clean-all: ## Remove everything including images and volumes
	docker-compose -f $(COMPOSE_FILE) down -v --rmi all
	docker system prune -f

.PHONY: update
update: ## Update container (rebuild and restart)
	make stop
	make build
	make run

# Setup commands
.PHONY: setup
setup: ## Initial setup - create directories and sample config
	mkdir -p logs config
	cp config.yaml.sample config/config.yaml || true
	@echo "Setup complete! Please edit config/config.yaml with your vCenter details."

.PHONY: env-example
env-example: ## Create .env.example file
	@echo "# VMware vCenter/ESXi Configuration" > .env.example
	@echo "VCENTER_HOST=your-vcenter-ip-or-hostname" >> .env.example
	@echo "VCENTER_USER=administrator@vsphere.local" >> .env.example
	@echo "VCENTER_PASSWORD=your-password" >> .env.example
	@echo "" >> .env.example
	@echo "# Optional VMware Configuration" >> .env.example
	@echo "VCENTER_DATACENTER=your-datacenter-name" >> .env.example
	@echo "VCENTER_CLUSTER=your-cluster-name" >> .env.example
	@echo "VCENTER_DATASTORE=your-datastore-name" >> .env.example
	@echo "VCENTER_NETWORK=VM Network" >> .env.example
	@echo "" >> .env.example
	@echo "# Security Settings" >> .env.example
	@echo "VCENTER_INSECURE=true" >> .env.example
	@echo "MCP_API_KEY=your-api-key-here" >> .env.example
	@echo "" >> .env.example
	@echo "# Logging Configuration" >> .env.example
	@echo "MCP_LOG_LEVEL=INFO" >> .env.example
	@echo ".env.example file created!"

# Health check
.PHONY: health
health: ## Check container health
	docker exec $(CONTAINER_NAME) python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080')" && echo "✅ Health check passed" || echo "❌ Health check failed"

# Quick start
.PHONY: quick-start
quick-start: ## Quick start with environment variables (requires .env file)
	@echo "Starting with environment variables..."
	@echo "Make sure you have created a .env file with your configuration!"
	docker-compose -f $(COMPOSE_FILE) up -d

.PHONY: dev
dev: build run-logs ## Development mode: build and run with logs 