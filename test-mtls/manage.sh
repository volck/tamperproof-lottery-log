#!/bin/bash
# Helper script for managing the test environment

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

function show_help() {
    echo -e "${BLUE}Lottery Log mTLS Test Environment Manager${NC}"
    echo ""
    echo "Usage: ./manage.sh [command]"
    echo ""
    echo "Commands:"
    echo "  setup       - Generate certificates and start services"
    echo "  start       - Start all services"
    echo "  stop        - Stop all services"
    echo "  restart     - Restart all services"
    echo "  logs        - Show logs from all services"
    echo "  logs-keycloak  - Show Keycloak logs"
    echo "  logs-tlog      - Show lottery-tlog logs"
    echo "  status      - Show service status"
    echo "  test        - Run authentication tests"
    echo "  clean       - Stop services and remove volumes"
    echo "  rebuild     - Rebuild and restart services"
    echo "  shell-tlog  - Open shell in tlog container"
    echo "  init-witness - Initialize witness certificates"
    echo "  add-draw    - Add a test lottery draw"
    echo "  help        - Show this help message"
    echo ""
}

function check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not found. Please install Docker first.${NC}"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}❌ docker-compose not found. Please install docker-compose first.${NC}"
        exit 1
    fi
}

function setup() {
    echo -e "${BLUE}🔧 Setting up test environment...${NC}"
    echo ""
    
    # Generate certificates
    if [ ! -d "ca" ] || [ ! -d "server" ] || [ ! -d "client" ]; then
        echo -e "${YELLOW}📋 Generating certificates...${NC}"
        ./generate-certs.sh
        echo ""
    else
        echo -e "${GREEN}✅ Certificates already exist${NC}"
        echo ""
    fi
    
    # Build and start services
    echo -e "${YELLOW}🏗️  Building and starting services...${NC}"
    docker-compose up --build -d
    
    echo ""
    echo -e "${GREEN}✅ Setup complete!${NC}"
    echo ""
    echo "Waiting for services to be ready..."
    sleep 5
    docker-compose ps
}

function start_services() {
    echo -e "${BLUE}🚀 Starting services...${NC}"
    docker-compose up -d
    echo ""
    echo "Waiting for services..."
    sleep 3
    docker-compose ps
}

function stop_services() {
    echo -e "${BLUE}🛑 Stopping services...${NC}"
    docker-compose down
    echo -e "${GREEN}✅ Services stopped${NC}"
}

function restart_services() {
    echo -e "${BLUE}🔄 Restarting services...${NC}"
    docker-compose restart
    echo ""
    sleep 3
    docker-compose ps
}

function show_logs() {
    docker-compose logs -f
}

function show_logs_keycloak() {
    docker-compose logs -f keycloak
}

function show_logs_tlog() {
    docker-compose logs -f lottery-tlog
}

function show_status() {
    echo -e "${BLUE}📊 Service Status${NC}"
    echo "===================="
    echo ""
    docker-compose ps
    echo ""
    
    # Check Keycloak health
    echo -e "${BLUE}Keycloak Health:${NC}"
    if curl -s -k https://localhost:8443/health/ready > /dev/null 2>&1; then
        echo -e "  ${GREEN}✅ Ready${NC}"
    else
        echo -e "  ${RED}❌ Not ready${NC}"
    fi
    
    # Check lottery-tlog health
    echo -e "${BLUE}Lottery-tlog Health:${NC}"
    if curl -s -k https://localhost:8080/api/status > /dev/null 2>&1; then
        echo -e "  ${GREEN}✅ Ready${NC}"
        echo ""
        echo -e "${BLUE}Tree Status:${NC}"
        curl -s -k https://localhost:8080/api/status | jq '.' || echo "  (jq not installed)"
    else
        echo -e "  ${RED}❌ Not ready${NC}"
    fi
    echo ""
}

function run_tests() {
    echo -e "${BLUE}🧪 Running authentication tests...${NC}"
    echo ""
    
    if [ ! -f "./test-auth.sh" ]; then
        echo -e "${RED}❌ test-auth.sh not found${NC}"
        exit 1
    fi
    
    ./test-auth.sh
}

function clean() {
    echo -e "${YELLOW}⚠️  This will remove all containers, volumes, and data${NC}"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}🧹 Cleaning up...${NC}"
        docker-compose down -v
        echo -e "${GREEN}✅ Cleanup complete${NC}"
    else
        echo "Cancelled"
    fi
}

function rebuild() {
    echo -e "${BLUE}🏗️  Rebuilding services...${NC}"
    docker-compose down
    docker-compose build --no-cache
    docker-compose up -d
    echo ""
    echo -e "${GREEN}✅ Rebuild complete${NC}"
    sleep 3
    docker-compose ps
}

function shell_tlog() {
    echo -e "${BLUE}🐚 Opening shell in lottery-tlog container...${NC}"
    docker-compose exec lottery-tlog /bin/sh
}

function init_witness() {
    echo -e "${BLUE}👁️  Initializing witness certificates...${NC}"
    echo ""
    
    read -p "Witness ID (e.g., witness1): " witness_id
    
    if [ -z "$witness_id" ]; then
        echo -e "${RED}❌ Witness ID required${NC}"
        exit 1
    fi
    
    # Run witness init in the container
    docker-compose exec lottery-tlog ./lottery-tlog witness init \
        --witness-id "$witness_id" \
        --name "Test Witness $witness_id"
    
    echo ""
    echo -e "${GREEN}✅ Witness initialized${NC}"
}

function add_draw() {
    echo -e "${BLUE}🎲 Adding test lottery draw...${NC}"
    echo ""
    
    # Create a sample draw JSON
    cat > /tmp/test-draw.json <<EOF
{
  "seq_no": 1,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "message": {
    "code": 300,
    "text": "Test lottery draw",
    "game_properties": {
      "game": 1,
      "draw": 1,
      "subdraw": 0
    }
  }
}
EOF

    # Copy to container and add draw
    docker cp /tmp/test-draw.json lottery-tlog-server:/tmp/draw.json
    docker-compose exec lottery-tlog ./lottery-tlog add-draw --file /tmp/draw.json
    
    rm /tmp/test-draw.json
    
    echo ""
    echo -e "${GREEN}✅ Draw added${NC}"
    echo ""
    echo "View status:"
    curl -s -k https://localhost:8080/api/status | jq '.' || echo "(jq not installed)"
}

# Main command handler
check_docker

case "${1:-help}" in
    setup)
        setup
        ;;
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    logs)
        show_logs
        ;;
    logs-keycloak)
        show_logs_keycloak
        ;;
    logs-tlog)
        show_logs_tlog
        ;;
    status)
        show_status
        ;;
    test)
        run_tests
        ;;
    clean)
        clean
        ;;
    rebuild)
        rebuild
        ;;
    shell-tlog)
        shell_tlog
        ;;
    init-witness)
        init_witness
        ;;
    add-draw)
        add_draw
        ;;
    help|*)
        show_help
        ;;
esac
