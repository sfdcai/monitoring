#!/bin/bash

# Datadog Agent Installation Script for Multiple Systems
# Detects system based on OS and installs/configures accordingly
# Prompts for API Key at runtime for secure GitHub hosting
# Datadog Site: datadoghq.com
# Date: April 22, 2025
# Usage: Run locally on each system: bash monitoring.sh

# Configuration
DATADOG_SITE="datadoghq.com"
LOG_FILE="/tmp/datadog_install_$(date +%F_%H-%M-%S).log"

# Function to log messages
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if running as root
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root"
    exit 1
  fi
}

# Function to prompt for API key
get_api_key() {
  read -sp "Enter your Datadog API Key: " API_KEY
  echo
  if [ -z "$API_KEY" ]; then
    log "ERROR: API Key cannot be empty"
    exit 1
  fi
  log "API Key received"
}

# Function to check network connectivity
check_network() {
  if ! ping -c 1 datadoghq.com >/dev/null 2>&1; then
    log "ERROR: No connectivity to datadoghq.com"
    exit 1
  fi
  log "Network connectivity to datadoghq.com confirmed"
}

# Function to check disk space
check_disk_space() {
  local path=$1
  local min_space_mb=$2
  local available_space
  # Use df -m and adjust awk to handle Alpine's df output (available space in 4th column, or 5th if % is present)
  available_space=$(df -m "$path" | tail -1 | awk '{print $(NF-2)}' | grep -o '[0-9]*')
  if [ -z "$available_space" ]; then
    log "ERROR: Unable to determine available disk space on $path"
    exit 1
  fi
  if [ "$available_space" -lt "$min_space_mb" ]; then
    log "ERROR: Insufficient disk space on $path (available: ${available_space}MB, required: ${min_space_mb}MB)"
    exit 1
  fi
  log "Sufficient disk space on $path (${available_space}MB available)"
}

# Function to validate log file paths
validate_log_path() {
  local path=$1
  if [ ! -f "$path" ] && [ ! -d "$path" ]; then
    log "WARNING: Log path $path does not exist, log collection may fail"
  else
    log "Log path $path validated"
  fi
}

# Function to validate placeholders
check_placeholders() {
  local file=$1
  local placeholder=$2
  if grep -q "$placeholder" "$file" 2>/dev/null; then
    log "ERROR: Placeholder $placeholder found in $file, please replace it"
    exit 1
  fi
}

# Function to detect system type based on OS
detect_system() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
  elif [ -f /etc/openwrt_release ]; then
    OS="openwrt"
  elif [ -f /etc/hassio-release ]; then
    OS="hassio"
  else
    log "ERROR: Cannot detect operating system"
    exit 1
  fi

  case "$OS" in
    "openwrt")
      SYSTEM="router"
      SYSTEM_NAME="router"
      ;;
    "debian")
      SYSTEM="proxmox"
      SYSTEM_NAME="proxmox"
      ;;
    "alpine")
      SYSTEM="alpine"
      # Prompt user to specify if this is the Docker Host
      echo "Is this the Docker Host system? (y/n)"
      read -r is_docker
      if [ "$is_docker" = "y" ] || [ "$is_docker" = "Y" ]; then
        IS_DOCKER_HOST="true"
        SYSTEM_NAME="docker-host"
      else
        IS_DOCKER_HOST="false"
        SYSTEM_NAME="adguard-home"
      fi
      ;;
    "hassio")
      SYSTEM="home-assistant"
      SYSTEM_NAME="home-assistant"
      ;;
    "ubuntu")
      SYSTEM="jellyfin"
      SYSTEM_NAME="jellyfin"
      ;;
    *)
      log "ERROR: Unsupported operating system: $OS"
      exit 1
      ;;
  esac
  log "Detected system: $SYSTEM (OS: $OS, Name: $SYSTEM_NAME)"
}

# Function to configure Datadog alerts
configure_alerts() {
  local system_name=$1
  local alert_type=$2
  local metric=$3
  local threshold=$4
  local message="Alert: $alert_type on $system_name"

  local api_url="https://api.datadoghq.com/api/v1/monitor"
  local query="avg(last_5m):avg:$metric{host:$system_name} $threshold"

  cat > /tmp/monitor.json <<EOF
{
  "type": "metric alert",
  "query": "$query",
  "name": "$alert_type on $system_name",
  "message": "$message",
  "tags": ["env:home"],
  "priority": 3,
  "options": {
    "thresholds": {
      "critical": $threshold
    },
    "notify_no_data": true,
    "no_data_timeframe": 10
  }
}
EOF

  if ! command -v curl >/dev/null; then
    log "ERROR: curl not installed, cannot configure alerts"
    rm -f /tmp/monitor.json
    return 1
  fi
  if ! command -v jq >/dev/null; then
    log "WARNING: jq not installed, alert configuration may fail"
  fi

  response=$(curl -s -X POST "$api_url" \
    -H "Content-Type: application/json" \
    -H "DD-API-KEY: $API_KEY" \
    -d @/tmp/monitor.json)
  if command -v jq >/dev/null && echo "$response" | jq -e '.id' >/dev/null; then
    log "Alert configured: $alert_type for $system_name"
  else
    log "ERROR: Failed to configure alert for $system_name: $response"
  fi
  rm -f /tmp/monitor.json
}

# Function to install on OpenWRT (Router)
install_router() {
  log "Installing Datadog monitoring for OpenWRT"
  if ! command -v opkg >/dev/null; then
    log "ERROR: opkg not found, is this OpenWRT?"
    exit 1
  fi
  check_disk_space "/" 10

  opkg update >>"$LOG_FILE" 2>&1 && opkg install snmpd >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install snmpd"
    exit 1
  fi

  cat > /etc/config/snmpd <<EOF
config system
    option syscontact 'admin@example.com'
    option syslocation 'Home Network'
config agent
    option agentaddress 'UDP:161'
config com2sec
    option name 'public'
    option community 'public'
    option source '192.168.1.0/24'
EOF
  /etc/init.d/snmpd restart >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to restart snmpd"
    exit 1
  fi

  uci set system.@system[0].log_ip=192.168.1.2
  uci commit system
  /etc/init.d/log restart >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to configure syslog"
    exit 1
  fi

  log "Router setup complete. SNMP metrics will be collected by Proxmox host."
}

# Function to install on Proxmox (Debian-based)
install_proxmox() {
  log "Installing Datadog Agent on Proxmox"
  if ! command -v apt-get >/dev/null; then
    log "ERROR: apt-get not found, is this Debian-based?"
    exit 1
  fi
  check_disk_space "/etc" 100

  apt-get update >>"$LOG_FILE" 2>&1 && apt-get install -y curl jq >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install curl and jq"
    exit 1
  fi

  DD_API_KEY=$API_KEY DD_SITE=$DATADOG_SITE bash -c "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script.sh)" >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install Datadog Agent"
    exit 1
  fi

  sed -i 's/# apm_config:/apm_config:\n  enabled: true\n  max_traces_per_second: 10/' /etc/datadog-agent/datadog.yaml
  sed -i 's/# logs_enabled: false/logs_enabled: true/' /etc/datadog-agent/datadog.yaml

  mkdir -p /etc/datadog-agent/conf.d/syslog.d
  cat > /etc/datadog-agent/conf.d/syslog.d/conf.yaml <<EOF
logs:
  - type: syslog
    port: 514
    source: syslog
    service: proxmox
    tags:
      - env:home
EOF

  mkdir -p /etc/datadog-agent/conf.d/snmp.d
  cat > /etc/datadog-agent/conf.d/snmp.d/conf.yaml <<EOF
init_config:
instances:
  - ip_address: 192.168.1.1
    community_string: public
    metrics:
      - MIB: IF-MIB
        table: ifTable
        symbols:
          - ifInOctets
          - ifOutOctets
      - MIB: IP-MIB
        symbols:
          - ipInReceives
          - ipOutRequests
EOF

  datadog-agent integration install -t datadog-proxmox==1.0.0 >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install Proxmox integration"
    exit 1
  fi
  mkdir -p /etc/datadog-agent/conf.d/proxmox.d
  cat > /etc/datadog-agent/conf.d/proxmox.d/conf.yaml <<EOF
init_config:
instances:
  - proxmox_endpoint: https://192.168.1.2:8006
    username: root@pam
    password: REPLACE_WITH_YOUR_PASSWORD
    verify_ssl: false
EOF
  check_placeholders "/etc/datadog-agent/conf.d/proxmox.d/conf.yaml" "REPLACE_WITH_YOUR_PASSWORD"

  systemctl restart datadog-agent >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to restart Datadog Agent"
    exit 1
  fi

  configure_alerts "proxmox" "High CPU Usage" "system.cpu.usage" "> 90"
  configure_alerts "proxmox" "Disk Full" "system.disk.in_use" "> 0.9"
  configure_alerts "proxmox" "Agent Failure" "datadog.agent.check_status" "> 0"

  log "Proxmox installation complete"
}

# Function to install on Alpine-based systems (AdGuard, Docker Host)
install_alpine() {
  local is_docker_host=$1
  local system_name=$2
  log "Installing Datadog Agent on Alpine ($system_name)"

  if ! command -v apk >/dev/null; then
    log "ERROR: apk not found, is this Alpine?"
    exit 1
  fi
  check_disk_space "/opt" 200
  check_disk_space "/tmp" 200

  # Install bash, curl, and jq
  apk add bash curl jq >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install bash, curl, and jq"
    exit 1
  fi

  # Download agent with validation
  local agent_url="https://s3.amazonaws.com/dd-agent/binaries/datadog-agent-latest.amd64-linux.tar.gz"
  curl -L "$agent_url" -o /tmp/datadog-agent.tar.gz >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ] || [ ! -s /tmp/datadog-agent.tar.gz ]; then
    log "ERROR: Failed to download Datadog Agent from $agent_url"
    exit 1
  fi

  # Extract agent
  tar -xzf /tmp/datadog-agent.tar.gz -C /opt >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to extract Datadog Agent to /opt"
    exit 1
  fi

  # Find extracted directory
  local agent_dir
  agent_dir=$(ls -d /opt/datadog-agent-* 2>/dev/null)
  if [ -z "$agent_dir" ]; then
    log "ERROR: No datadog-agent directory found in /opt after extraction"
    exit 1
  fi
  mv "$agent_dir" /opt/datadog-agent >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to rename $agent_dir to /opt/datadog-agent"
    exit 1
  fi
  rm /tmp/datadog-agent.tar.gz

  # Configure agent
  mkdir -p /etc/datadog-agent
  cat > /etc/datadog-agent/datadog.yaml <<EOF
api_key: $API_KEY
site: $DATADOG_SITE
hostname: $system_name
apm_config:
  enabled: true
  max_traces_per_second: 10
logs_enabled: true
EOF

  # Set up service
  cat > /etc/init.d/datadog-agent <<EOF
#!/sbin/openrc-run
name="datadog-agent"
command="/opt/datadog-agent/bin/agent/agent"
command_args="start"
pidfile="/var/run/datadog-agent.pid"
depend() {
    need net
}
EOF
  chmod +x /etc/init.d/datadog-agent
  rc-update add datadog-agent default
  rc-service datadog-agent start >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to start Datadog Agent. Check /opt/datadog-agent/logs/ for details"
    exit 1
  fi

  if [ "$is_docker_host" = "false" ]; then
    mkdir -p /etc/datadog-agent/conf.d/adguard.d
    cat > /etc/datadog-agent/conf.d/adguard.d/conf.yaml <<EOF
logs:
  - type: file
    path: /var/log/adguardhome.log
    source: adguard
    service: adguard
    tags:
      - env:home
EOF
    validate_log_path "/var/log/adguardhome.log"
    mkdir -p /etc/datadog-agent/conf.d/http_check.d
    cat > /etc/datadog-agent/conf.d/http_check.d/conf.yaml <<EOF
init_config:
instances:
  - name: adguard_stats
    url: http://192.168.1.3:80/stats
    metrics:
      - total_queries
      - blocked_queries
    tags:
      - env:home
EOF
    rc-service datadog-agent restart >>"$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
      log "ERROR: Failed to restart Datadog Agent after AdGuard configuration"
      exit 1
    fi
    configure_alerts "adguard-home" "High Blocked Queries" "adguard.blocked_queries" "> 1000"
    configure_alerts "adguard-home" "Agent Failure" "datadog.agent.check_status" "> 0"
  fi

  if [ "$is_docker_host" = "true" ]; then
    apk add docker docker-compose >>"$LOG_FILE" 2>&1
    rc-update add docker default
    rc-service docker start >>"$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
      log "ERROR: Failed to install/start Docker"
      exit 1
    fi

    docker run -d --name dd-agent \
      -v /var/run/docker.sock:/var/run/docker.sock:ro \
      -v /proc/:/host/proc/:ro \
      -v /sys/fs/cgroup/:/host/sys/fs/cgroup:ro \
      -e DD_API_KEY=$API_KEY \
      -e DD_SITE=$DATADOG_SITE \
      -e DD_APM_ENABLED=true \
      -e DD_LOGS_ENABLED=true \
      -e DD_DOGSTATSD_NON_LOCAL_TRAFFIC=true \
      -p 127.0.0.1:8126:8126/tcp \
      gcr.io/datadoghq/agent:latest >>"$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
      log "ERROR: Failed to start Datadog Agent container"
      exit 1
    fi

    mkdir -p /etc/datadog-agent/conf.d/docker.d
    cat > /etc/datadog-agent/conf.d/docker.d/conf.yaml <<EOF
init_config:
instances:
  - docker_sock: unix:///var/run/docker.sock
    tags:
      - env:home
logs:
  - type: docker
    source: docker
    service: docker
    tags:
      - env:home
EOF
    rc-service datadog-agent restart >>"$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
      log "ERROR: Failed to restart Datadog Agent after Docker configuration"
      exit 1
    fi

    if [ -f "/docker-compose.yml" ]; then
      cp /docker-compose.yml /docker-compose.yml.bak
      log "Backed up existing docker-compose.yml to /docker-compose.yml.bak"
      cat > /tmp/docker-compose-datadog.yml <<EOF
version: '3'
services:
  sonarr:
    image: linuxserver/sonarr
    labels:
      com.datadoghq.ad.logs: '[{"source":"sonarr","service":"sonarr"}]'
      com.datadoghq.ad.check_names: '["http_check"]'
      com.datadoghq.ad.init_configs: '[{}]'
      com.datadoghq.ad.instances: '[{"name":"sonarr","url":"http://localhost:8989"}]'
  prowlarr:
    image: linuxserver/prowlarr
    labels:
      com.datadoghq.ad.logs: '[{"source":"prowlarr","service":"prowlarr"}]'
  radarr:
    image: linuxserver/radarr
    labels:
      com.datadoghq.ad.logs: '[{"source":"radarr","service":"radarr"}]'
  bazarr:
    image: linuxserver/bazarr
    labels:
      com.datadoghq.ad.logs: '[{"source":"bazarr","service":"bazarr"}]'
  whisparr:
    image: linuxserver/whisparr
    labels:
      com.datadoghq.ad.logs: '[{"source":"whisparr","service":"whisparr"}]'
  qbittorrent:
    image: linuxserver/qbittorrent
    labels:
      com.datadoghq.ad.logs: '[{"source":"qbittorrent","service":"qbittorrent"}]'
      com.datadoghq.ad.check_names: '["http_check"]'
      com.datadoghq.ad.init_configs: '[{}]'
      com.datadoghq.ad.instances: '[{"name":"qbittorrent","url":"http://localhost:8080"}]'
  portainer:
    image: portainer/portainer-ce
    labels:
      com.datadoghq.ad.logs: '[{"source":"portainer","service":"portainer"}]'
EOF
      log "Generated Datadog-specific docker-compose file at /tmp/docker-compose-datadog.yml"
      log "Manually merge with existing docker-compose.yml if needed"
    else
      log "WARNING: docker-compose.yml not found, skipping container labels"
    fi

    configure_alerts "docker-host" "Container Down" "docker.containers.running" "< 7"
    configure_alerts "docker-host" "High Memory" "docker.mem.rss" "> 1000000000"
  fi

  log "Alpine ($system_name) installation complete"
}

# Function to install on Home Assistant OS
install_home_assistant() {
  log "Installing Datadog Agent on Home Assistant OS"
  if ! command -v docker >/dev/null; then
    log "ERROR: docker not found, is this Home Assistant OS?"
    exit 1
  fi
  check_disk_space "/" 200

  docker run -d --name dd-agent \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v /proc/:/host/proc/:ro \
    -v /sys/fs/cgroup/:/host/sys/fs/cgroup:ro \
    -e DD_API_KEY=$API_KEY \
    -e DD_SITE=$DATADOG_SITE \
    -e DD_APM_ENABLED=true \
    -e DD_LOGS_ENABLED=true \
    -p 127.0.0.1:8126:8126/tcp \
    gcr.io/datadoghq/agent:latest >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to start Datadog Agent container"
    exit 1
  fi

  mkdir -p /etc/datadog-agent/conf.d/homeassistant.d
  cat > /etc/datadog-agent/conf.d/homeassistant.d/conf.yaml <<EOF
logs:
  - type: file
    path: /config/home-assistant.log
    source: homeassistant
    service: homeassistant
    tags:
      - env:home
init_config:
instances:
  - url: http://192.168.1.10:8123
    token: REPLACE_WITH_YOUR_HA_TOKEN
    tags:
      - env:home
EOF
  validate_log_path "/config/home-assistant.log"
  check_placeholders "/etc/datadog-agent/conf.d/homeassistant.d/conf.yaml" "REPLACE_WITH_YOUR_HA_TOKEN"

  docker restart dd-agent >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to restart Datadog Agent container"
    exit 1
  fi

  configure_alerts "home-assistant" "Service Down" "homeassistant.up" "== 0"
  configure_alerts "home-assistant" "High CPU" "system.cpu.usage" "> 80"

  log "Home Assistant installation complete"
}

# Function to install on Jellyfin (Ubuntu-based)
install_jellyfin() {
  log "Installing Datadog Agent on Jellyfin (Ubuntu)"
  if ! command -v apt-get >/dev/null; then
    log "ERROR: apt-get not found, is this Ubuntu?"
    exit 1
  fi
  check_disk_space "/etc" 100

  apt-get update >>"$LOG_FILE" 2>&1 && apt-get install -y curl jq >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install curl and jq"
    exit 1
  fi

  DD_API_KEY=$API_KEY DD_SITE=$DATADOG_SITE bash -c "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script.sh)" >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install Datadog Agent"
    exit 1
  fi

  sed -i 's/# apm_config:/apm_config:\n  enabled: true\n  max_traces_per_second: 10/' /etc/datadog-agent/datadog.yaml
  sed -i 's/# logs_enabled: false/logs_enabled: true/' /etc/datadog-agent/datadog.yaml

  mkdir -p /etc/datadog-agent/conf.d/jellyfin.d
  cat > /etc/datadog-agent/conf.d/jellyfin.d/conf.yaml <<EOF
logs:
  - type: file
    path: /var/log/jellyfin/*.log
    source: jellyfin
    service: jellyfin
    tags:
      - env:home
EOF
  validate_log_path "/var/log/jellyfin"
  mkdir -p /etc/datadog-agent/conf.d/http_check.d
  cat > /etc/datadog-agent/conf.d/http_check.d/conf.yaml <<EOF
init_config:
instances:
  - name: jellyfin
    url: http://192.168.1.11:8096/health
    tags:
      - env:home
EOF

  systemctl restart datadog-agent >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to restart Datadog Agent"
    exit 1
  fi

  configure_alerts "jellyfin" "Service Down" "http_check.status" "!= 1"
  configure_alerts "jellyfin" "High Memory" "system.mem.used" "> 80"

  log "Jellyfin installation complete"
}

# Main execution
log "Starting Datadog Agent installation"

# Check root privileges
check_root

# Prompt for API key
get_api_key

# Check network connectivity
check_network

# Detect system
detect_system

# Install based on system type
case $SYSTEM in
  "router")
    install_router
    ;;
  "proxmox")
    install_proxmox
    ;;
  "alpine")
    install_alpine "$IS_DOCKER_HOST" "$SYSTEM_NAME"
    ;;
  "home-assistant")
    install_home_assistant
    ;;
  "jellyfin")
    install_jellyfin
    ;;
esac

# Verification steps
log "Installation complete. Verifying setup..."
if [ "$SYSTEM" = "router" ]; then
  if pgrep snmpd >/dev/null; then
    log "SNMP service is running"
  else
    log "ERROR: SNMP service not running"
  fi
else
  if [ "$SYSTEM" = "home-assistant" ]; then
    if docker ps | grep dd-agent >/dev/null; then
      log "Datadog Agent container is running"
    else
      log "ERROR: Datadog Agent container not running"
    fi
  else
    if [ "$OS" = "alpine" ]; then
      if rc-service datadog-agent status | grep started >/dev/null; then
        log "Datadog Agent service is running"
      else
        log "ERROR: Datadog Agent service not running"
      fi
    else
      if systemctl is-active datadog-agent >/dev/null; then
        log "Datadog Agent service is running"
      else
        log "ERROR: Datadog Agent service not running"
      fi
    fi
  fi
fi

log "Setup complete. Check $LOG_FILE for details."
log "Next steps:"
log "- Replace placeholders (e.g., REPLACE_WITH_YOUR_PASSWORD, REPLACE_WITH_YOUR_HA_TOKEN)"
log "- Verify metrics in Datadog UI: https://app.datadoghq.com/metric/explorer"
log "- Check logs in /var/log/datadog/ (Debian/Ubuntu) or /opt/datadog-agent/logs/ (Alpine) or Docker logs (Home Assistant)"
log "- For APM, instrument applications (see https://docs.datadoghq.com/tracing/setup_overview/)"
