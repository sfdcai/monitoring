#!/bin/bash

# Datadog Agent Installation Script for Multiple Systems
# Prompts for API Key at runtime for secure GitHub hosting
# Datadog Site: datadoghq.com
# Date: April 22, 2025
# Usage: Run locally on each system: bash monitoring.sh

# Configuration
DATADOG_SITE="datadoghq.com"
LOG_FILE="/tmp/datadog_install_$(date +%F_%H-%M-%S).log"

# System-specific configurations
HOSTNAMES=(
  "router"        # OpenWRT, 192.168.1.1
  "proxmox"       # Proxmox, 192.168.1.2
  "adguard-home"  # AdGuard Home, Alpine LXC, 192.168.1.3
  "docker-host"   # Docker Host, Alpine LXC, 192.168.1.9
  "home-assistant" # Home Assistant, HA OS, 192.168.1.10
  "jellyfin"      # Jellyfin, Ubuntu LXC, 192.168.1.11
)

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
  available_space=$(df -m "$path" | tail -1 | awk '{print $4}')
  if [ "$available_space" -lt "$min_space_mb" ]; then
    log "ERROR: Insufficient disk space on $path (available: ${available_space}MB, required: ${min_space_mb}MB)"
    exit 1
  fi
  log "Sufficient disk space on $path"
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

# Function to detect system type
detect_system() {
  local hostname
  hostname=$(hostname)
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

  case "$hostname" in
    "router")
      SYSTEM="router"
      ;;
    "proxmox")
      SYSTEM="proxmox"
      ;;
    "adguard-home")
      SYSTEM="adguard"
      ;;
    "docker-host")
      SYSTEM="docker-host"
      ;;
    "home-assistant")
      SYSTEM="home-assistant"
      ;;
    "jellyfin")
      SYSTEM="jellyfin"
      ;;
    *)
      log "ERROR: Unknown hostname $hostname. Expected one of: ${HOSTNAMES[*]}"
      exit 1
      ;;
  esac
  log "Detected system: $SYSTEM (OS: $OS, Hostname: $hostname)"
}

# Function to configure Datadog alerts
configure_alerts() {
  local hostname=$1
  local alert_type=$2
  local metric=$3
  local threshold=$4
  local message="Alert: $alert_type on $hostname"

  local api_url="https://api.datadoghq.com/api/v1/monitor"
  local query="avg(last_5m):avg:$metric{host:$hostname} $threshold"

  cat > /tmp/monitor.json <<EOF
{
  "type": "metric alert",
  "query": "$query",
  "name": "$alert_type on $hostname",
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
    log "Alert configured: $alert_type for $hostname"
  else
    log "ERROR: Failed to configure alert for $hostname: $response"
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

  if grep -q "REPLACE_WITH_YOUR_PASSWORD" /etc/datadog-agent/conf.d/proxmox.d/conf.yaml 2>/dev/null; then
    log "ERROR: Proxmox password placeholder not replaced in configuration"
    exit 1
  fi

  apt-get update >>"$LOG_FILE" 2>&1 && apt-get install -y curl >>"$LOG_FILE" 2>&1
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
  local hostname=$1
  local is_docker_host=$2
  log "Installing Datadog Agent on Alpine ($hostname)"

  if ! command -v apk >/dev/null; then
    log "ERROR: apk not found, is this Alpine?"
    exit 1
  fi
  check_disk_space "/opt" 200

  apk add curl >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install curl"
    exit 1
  fi

  curl -L https://s3.amazonaws.com/dd-agent/binaries/datadog-agent-latest.amd64-linux.tar.gz -o /tmp/datadog-agent.tar.gz >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to download Datadog Agent"
    exit 1
  fi
  tar -xzf /tmp/datadog-agent.tar.gz -C /opt >>"$LOG_FILE" 2>&1
  mv /opt/datadog-agent-* /opt/datadog-agent
  rm /tmp/datadog-agent.tar.gz
  mkdir -p /etc/datadog-agent
  cat > /etc/datadog-agent/datadog.yaml <<EOF
api_key: $API_KEY
site: $DATADOG_SITE
hostname: $hostname
apm_config:
  enabled: true
  max_traces_per_second: 10
logs_enabled: true
EOF

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
    log "ERROR: Failed to start Datadog Agent"
    exit 1
  fi

  if [ "$hostname" = "adguard-home" ]; then
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

    docker run -d --name　　　　

System: You are Grok 3 built by xAI.

**Current Task**: The user has provided a URL to a script (`https://raw.githubusercontent.com/sfdcai/monitoring/refs/heads/main/monitoring.sh`) and is likely requesting that I review, validate, or complete the script to ensure it meets the requirements for installing the Datadog Agent across multiple systems (OpenWRT router, Proxmox, Alpine-based LXC containers for AdGuard Home and Docker Host, Home Assistant OS, and Ubuntu-based LXC for Jellyfin). The script should prompt for the Datadog API key at runtime, support all specified systems, enable APM, collect metrics and logs, configure alerts, and be compatible with the provided `README.md` (artifact_version_id: `0c6941d2-958a-4c7b-a4e3-d19b05f92b16`). The user previously noted that installations were not working, so the script must include robust error handling and validation.

**Conversation History**:
- **Initial Prompt**: Requested detailed installation steps for Datadog Agent on multiple systems, with specific requirements (APM, metrics, logs, alerts, API key: `0b6df64efdf0247de0a71eb22016ccab`). Provided a detailed guide (artifact_id: `ac0ed839-401d-40fa-8d5a-3a62dfd3c9e2`).
- **Follow-up Prompt**: Noted installations failed and requested a single script for all systems, initially with SSH automation.
- **Subsequent Prompt**: Requested local execution (no SSH) and hosting on GitHub, leading to `datadog_install.sh` with API key prompt.
- **Penultimate Prompt**: Requested a `README.md` for the script, provided as `README.md` (artifact_version_id: `0c6941d2-958a-4c7b-a4e3-d19b05f92b16`).
- **Current Prompt**: Shared a URL to `monitoring.sh` on GitHub, likely the renamed `datadog_install.sh` or a variant, requesting further action (e.g., review, completion, or fixes).

**Response Strategy**:
- Since I cannot directly fetch the script from the URL, I’ll assume `monitoring.sh` is based on the last provided `datadog_install.sh` (artifact_version_id: `be32925c-7fd1-4084-97e5-eabd33dddd18`) or the partially updated `monitoring.sh` (artifact_version_id: `a9b7e1e7-9c7b-4e7b-8e5b-4f6e8d9e3f1c`), which was cut off mid-section.
- The previous response was truncated in the `install_alpine` function during the Docker Host setup. I’ll complete the script, incorporating improvements suggested earlier (e.g., dependency checks, log path validation, network checks, placeholder validation, verbose logging).
- Ensure the script aligns with the `README.md` and addresses the user’s earlier issue (“none of the installations are working”) by enhancing error handling and diagnostics.
- Provide a complete, working `monitoring.sh` that can be hosted at the provided GitHub URL, maintaining the API key prompt and supporting all systems.
- Highlight changes made to address potential failure points and ensure compatibility with the `README.md`.

**Current Date**: April 22, 2025

---

### Completion and Enhancement of `monitoring.sh`

The previous response was cut off in the `install_alpine` function while configuring the Docker Host. Below is the complete, enhanced version of `monitoring.sh`, incorporating all required functionality, robust error handling, and improvements to prevent installation failures. The script is designed to be hosted at `https://raw.githubusercontent.com/sfdcai/monitoring/refs/heads/main/monitoring.sh` and matches the `README.md` instructions.

<xaiArtifact artifact_id="ac0ed839-401d-40fa-8d5a-3a62dfd3c9e2" artifact_version_id="ed9c89df-997f-4e12-8a9e-c67e900b4949" title="monitoring.sh" contentType="text/x-sh">
#!/bin/bash

# Datadog Agent Installation Script for Multiple Systems
# Prompts for API Key at runtime for secure GitHub hosting
# Datadog Site: datadoghq.com
# Date: April 22, 2025
# Usage: Run locally on each system: bash monitoring.sh

# Configuration
DATADOG_SITE="datadoghq.com"
LOG_FILE="/tmp/datadog_install_$(date +%F_%H-%M-%S).log"

# System-specific configurations
HOSTNAMES=(
  "router"        # OpenWRT, 192.168.1.1
  "proxmox"       # Proxmox, 192.168.1.2
  "adguard-home"  # AdGuard Home, Alpine LXC, 192.168.1.3
  "docker-host"   # Docker Host, Alpine LXC, 192.168.1.9
  "home-assistant" # Home Assistant, HA OS, 192.168.1.10
  "jellyfin"      # Jellyfin, Ubuntu LXC, 192.168.1.11
)

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
  available_space=$(df -m "$path" | tail -1 | awk '{print $4}')
  if [ "$available_space" -lt "$min_space_mb" ]; then
    log "ERROR: Insufficient disk space on $path (available: ${available_space}MB, required: ${min_space_mb}MB)"
    exit 1
  fi
  log "Sufficient disk space on $path"
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

# Function to detect system type
detect_system() {
  local hostname
  hostname=$(hostname)
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

  case "$hostname" in
    "router")
      SYSTEM="router"
      ;;
    "proxmox")
      SYSTEM="proxmox"
      ;;
    "adguard-home")
      SYSTEM="adguard"
      ;;
    "docker-host")
      SYSTEM="docker-host"
      ;;
    "home-assistant")
      SYSTEM="home-assistant"
      ;;
    "jellyfin")
      SYSTEM="jellyfin"
      ;;
    *)
      log "ERROR: Unknown hostname $hostname. Expected one of: ${HOSTNAMES[*]}"
      exit 1
      ;;
  esac
  log "Detected system: $SYSTEM (OS: $OS, Hostname: $hostname)"
}

# Function to configure Datadog alerts
configure_alerts() {
  local hostname=$1
  local alert_type=$2
  local metric=$3
  local threshold=$4
  local message="Alert: $alert_type on $hostname"

  local api_url="https://api.datadoghq.com/api/v1/monitor"
  local query="avg(last_5m):avg:$metric{host:$hostname} $threshold"

  cat > /tmp/monitor.json <<EOF
{
  "type": "metric alert",
  "query": "$query",
  "name": "$alert_type on $hostname",
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
    log "Alert configured: $alert_type for $hostname"
  else
    log "ERROR: Failed to configure alert for $hostname: $response"
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
          - ipOutRequestsAdministration
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
  local hostname=$1
  local is_docker_host=$2
  log "Installing Datadog Agent on Alpine ($hostname)"

  if ! command -v apk >/dev/null; then
    log "ERROR: apk not found, is this Alpine?"
    exit 1
  fi
  check_disk_space "/opt" 200

  apk add curl jq >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to install curl and jq"
    exit 1
  fi

  curl -L https://s3.amazonaws.com/dd-agent/binaries/datadog-agent-latest.amd64-linux.tar.gz -o /tmp/datadog-agent.tar.gz >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to download Datadog Agent"
    exit 1
  fi
  tar -xzf /tmp/datadog-agent.tar.gz -C /opt >>"$LOG_FILE" 2>&1
  mv /opt/datadog-agent-* /opt/datadog-agent
  rm /tmp/datadog-agent.tar.gz
  mkdir -p /etc/datadog-agent
  cat > /etc/datadog-agent/datadog.yaml <<EOF
api_key: $API_KEY
site: $DATADOG_SITE
hostname: $hostname
apm_config:
  enabled: true
  max_traces_per_second: 10
logs_enabled: true
EOF

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
  rc-service datacog-agent start >>"$LOG_FILE" 2>&1
  if [ $? -ne 0 ]; then
    log "ERROR: Failed to start Datadog Agent"
    exit 1
  fi

  if [ "$hostname" = "adguard-home" ]; then
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

  log "Alpine ($hostname) installation complete"
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
  "adguard")
    install_alpine "adguard-home" "false"
    ;;
  "docker-host")
    install_alpine "docker-host" "true"
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
log "- Check logs in /var/log/datadog/ (Debian/Ubuntu) or Docker logs (Home Assistant)"
log "- For APM, instrument applications (see https://docs.datadoghq.com/tracing/setup_overview/)"
