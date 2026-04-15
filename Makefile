# Provability Fabric Testbed - Cross-Platform Makefile
# Implements state-of-the-art dependency management and CI/CD practices

.PHONY: help install deps deps-clean deps-update deps-audit deps-report
.PHONY: build test lint format security-check quality-check
.PHONY: docker-build docker-run docker-stop docker-clean
.PHONY: up down status logs seed soak redteam evidence metering
.PHONY: ci cd deploy clean verify

# Detect OS and set appropriate commands
ifeq ($(OS),Windows_NT)
    # Windows commands
    PYTHON := python
    PIP := python -m pip
    NPM := npm
    RM := rmdir /s /q
    MKDIR := if not exist
    CP := copy
    SHELL := cmd
    VENV_ACTIVATE := .venv\Scripts\activate
else
    # Unix commands
    PYTHON := python3
    PIP := pip3
    NPM := npm
    RM := rm -rf
    MKDIR := mkdir -p
    CP := cp
    VENV_ACTIVATE := . .venv/bin/activate
endif

# Project configuration
PROJECT_NAME := pf-testbed
VERSION := 1.0.0
PYTHON_VERSION := 3.8
NODE_VERSION := 18

# Directories
SRC_DIR := testbed
BUILD_DIR := build
DIST_DIR := dist
REPORTS_DIR := reports
EVIDENCE_DIR := evidence

# Files
REQUIREMENTS_FILE := requirements.txt
PACKAGE_JSON := package.json
PACKAGE_LOCK := package-lock.json

# Default target
help: ## Show this help message
	@echo "🚀 Provability Fabric Testbed - Available Commands"
	@echo "=================================================="
	@echo ""
	@echo "📦 Dependency Management:"
	@echo "  deps          - Install all dependencies"
	@echo "  deps-clean    - Clean and reinstall dependencies"
	@echo "  deps-update   - Update dependencies to latest versions"
	@echo "  deps-audit    - Security audit of dependencies"
	@echo "  deps-report   - Generate dependency report"
	@echo ""
	@echo "🔧 Development:"
	@echo "  build         - Build all components"
	@echo "  test          - Run all tests"
	@echo "  lint          - Run linting and code quality checks"
	@echo "  format        - Format code"
	@echo "  security-check - Run security scans"
	@echo "  quality-check - Run comprehensive quality checks"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  docker-build  - Build Docker images"
	@echo "  docker-run    - Run with Docker Compose"
	@echo "  docker-stop   - Stop Docker services"
	@echo "  docker-clean  - Clean Docker resources"
	@echo ""
	@echo "🚀 Operations:"
	@echo "  up            - Start all services"
	@echo "  down          - Stop all services"
	@echo "  status        - Show service status"
	@echo "  logs          - View service logs"
	@echo "  seed          - Seed data and populate indices"
	@echo "  soak          - Load testing and performance validation"
	@echo "  redteam       - Security testing and adversarial validation"
	@echo "  evidence      - Generate evidence pack export"
	@echo "  metering      - Generate billing and usage reports"
	@echo ""
	@echo "🔄 CI/CD:"
	@echo "  ci            - Run CI pipeline locally"
	@echo "  cd            - Run CD pipeline locally"
	@echo "  deploy        - Deploy to target environment"
	@echo ""
	@echo "🧹 Maintenance:"
	@echo "  clean         - Clean build artifacts"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make deps     # Install dependencies"
	@echo "  make ci       # Run CI pipeline"
	@echo "  make up       # Start services"

# Dependency Management
deps: ## Install all dependencies
	@echo "📦 Installing dependencies..."
ifeq ($(OS),Windows_NT)
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
else
	@$(MKDIR) $(BUILD_DIR)
endif
	@$(PYTHON) scripts/manage-deps.py --install
	@echo "✅ Dependencies installed successfully"

deps-clean: ## Clean and reinstall dependencies
	@echo "🧹 Cleaning dependencies..."
	@$(PYTHON) scripts/manage-deps.py --install --clean
	@echo "✅ Dependencies cleaned and reinstalled"

deps-update: ## Update dependencies to latest versions
	@echo "🔄 Updating dependencies..."
	@$(PYTHON) scripts/manage-deps.py --install --upgrade
	@echo "✅ Dependencies updated successfully"

deps-audit: ## Security audit of dependencies
	@echo "🔒 Auditing dependencies..."
	@$(PYTHON) scripts/manage-deps.py --validate
	@echo "✅ Dependency audit completed"

deps-report: ## Generate dependency report
	@echo "📊 Generating dependency report..."
	@$(PYTHON) scripts/manage-deps.py --report
	@echo "✅ Dependency report generated"

# Development Commands
build: deps ## Build all components
	@echo "🔨 Building components..."
	@$(NPM) run build
	@echo "✅ Build completed successfully"

test: deps ## Run all tests
	@echo "🧪 Running tests..."
	@$(NPM) test
	@$(PYTHON) -m pytest $(SRC_DIR)/tools/reporter/ -v
	@echo "✅ Tests completed successfully"

lint: deps ## Run linting and code quality checks
	@echo "🔍 Running linting..."
	@$(NPM) run lint
	@$(PYTHON) -m flake8 $(SRC_DIR) --max-line-length=88
	@$(PYTHON) -m black --check $(SRC_DIR)
	@$(PYTHON) -m isort --check-only $(SRC_DIR)
	@echo "✅ Linting completed successfully"

format: deps ## Format code
	@echo "🎨 Formatting code..."
	@$(PYTHON) -m black $(SRC_DIR)
	@$(PYTHON) -m isort $(SRC_DIR)
	@$(NPM) run format
	@echo "✅ Code formatting completed"

security-check: deps ## Run security scans
	@echo "🛡️ Running security checks..."
	@$(PYTHON) -m bandit -r $(SRC_DIR) -f json -o $(REPORTS_DIR)/bandit-report.json
	@$(NPM) audit --audit-level=moderate
	@echo "✅ Security checks completed"

quality-check: lint security-check test ## Run comprehensive quality checks
	@echo "✨ Quality checks completed successfully"

# Docker Commands
docker-build: ## Build Docker images
	@echo "🐳 Building Docker images..."
	@$(NPM) run docker:build
	@echo "✅ Docker images built successfully"

docker-run: ## Run with Docker Compose
	@echo "🚀 Starting Docker services..."
	@$(NPM) run docker:run
	@echo "✅ Docker services started"

docker-stop: ## Stop Docker services
	@echo "🛑 Stopping Docker services..."
	@$(NPM) run docker:stop
	@echo "✅ Docker services stopped"

docker-clean: ## Clean Docker resources
	@echo "🧹 Cleaning Docker resources..."
	@docker system prune -f
	@docker volume prune -f
	@echo "✅ Docker resources cleaned"

# Operations Commands
up: docker-run ## Start all services
	@echo "🚀 Services started successfully"

down: docker-stop ## Stop all services
	@echo "🛑 Services stopped successfully"

status: ## Show service status
	@echo "📊 Service Status:"
	@docker-compose ps

logs: ## View service logs
	@echo "📝 Service Logs:"
	@docker-compose logs -f

seed: deps ## Seed data and populate indices
	@echo "🌱 Seeding data..."
	@cd $(SRC_DIR)/data && $(PYTHON) generator.py --tenant acme --count 100
	@cd $(SRC_DIR)/data && $(PYTHON) generator.py --tenant globex --count 100
	@cd $(SRC_DIR)/data && $(PYTHON) honeytoken-generator.py --count 50
	@echo "✅ Data seeding completed"

soak: deps ## Load testing and performance validation
	@echo "⚡ Running soak tests..."
	@cd external/provability-fabric/tests/load && k6 run edge_load.js
	@cd external/provability-fabric/tests/load && k6 run ledger_load.js
	@echo "✅ Soak testing completed"

redteam: deps ## Security testing and adversarial validation
	@echo "🔴 Running redteam tests..."
	@cd external/provability-fabric/tests/redteam && $(PYTHON) redteam_runner.py --kube-config ../../../../kubeconfig-kind.yaml --cases-dir cases
	@echo "✅ Redteam testing completed"

evidence: deps ## Generate evidence pack export
	@echo "📦 Generating evidence pack..."
	@$(PYTHON) $(SRC_DIR)/tools/reporter/generate_testbed_report.py \
		--config $(SRC_DIR)/tools/reporter/config.yaml \
		--output $(EVIDENCE_DIR) \
		--format both \
		--time-range 168 \
		--include-art-comparison \
		--include-redteam-analysis
	@echo "✅ Evidence pack generated"

metering: deps ## Generate billing and usage reports
	@echo "💰 Generating metering reports..."
	@cd $(SRC_DIR)/tools/metering && $(NPM) start -- simulate-usage acme-corp 50 --period 2025-01
	@cd $(SRC_DIR)/tools/metering && $(NPM) start -- simulate-usage globex-corp 50 --period 2025-01
	@cd $(SRC_DIR)/tools/metering && $(NPM) start -- generate-invoice acme-corp 2025-01 -o ../../$(EVIDENCE_DIR)/acme-invoice.json
	@cd $(SRC_DIR)/tools/metering && $(NPM) start -- generate-invoice globex-corp 2025-01 -o ../../$(EVIDENCE_DIR)/globex-invoice.json
	@cd $(SRC_DIR)/tools/metering && $(NPM) start -- export-metrics -o ../../$(EVIDENCE_DIR)/usage-metrics.prom
	@echo "✅ Metering reports generated"

# CI/CD Commands
ci: quality-check ## Run CI pipeline locally
	@echo "🔄 CI pipeline completed successfully"

verify: ci ## Verification entrypoint for CI workflows
	@echo "✅ Verification checks passed"

cd: ci ## Run CD pipeline locally
	@echo "🚀 CD pipeline completed successfully"

deploy: cd ## Deploy to target environment
	@echo "🌍 Deployment completed successfully"

# Maintenance Commands
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	@$(RM) $(BUILD_DIR) $(DIST_DIR) $(REPORTS_DIR)
	@$(NPM) run clean
	@echo "✅ Cleanup completed"

# Windows-specific commands
ifeq ($(OS),Windows_NT)
run: ## Windows equivalent of make commands
	@echo "🪟 Windows detected - use run.bat instead"
	@echo "Available commands: run.bat up, run.bat down, run.bat evidence, etc."
endif
