# Datadog Agent Installation Script

This Bash script automates the installation and configuration of the Datadog Agent across multiple systems in a home network. It supports a variety of operating systems and services, enabling system and application metric collection, log collection, Application Performance Monitoring (APM), and alerting for resource usage and service failures. The script is designed to be hosted on GitHub and executed locally on each system.

## Supported Systems

The script supports the following systems, each with specific installation methods and configurations:

- **Router**: Linksys WRT 1900ACS, OpenWRT (192.168.1.1)
  - Configures SNMP for network metrics and syslog forwarding to Proxmox.
- **Proxmox Host**: Mac Mini Late 2014, Proxmox (192.168.1.2)
  - Uses Debian package installation, includes Proxmox integration and SNMP for router metrics.
- **AdGuard Home**: LXC, Alpine (192.168.1.3)
  - Uses static binary installation due to musl libc, configures AdGuard metrics and logs.
- **Docker Host**: LXC, Alpine (192.168.1.9)
  - Uses static binary for host and Docker container for container monitoring, supports Sonarr, Prowlarr, Radarr, Bazarr, Whisparr, qBittorrent, and Portainer.
- **Home Assistant**: VM, Home Assistant OS (192.168.1.10)
  - Uses Docker-based installation, configures Home Assistant metrics and logs.
- **Jellyfin**: LXC, Ubuntu (192.168.1.11)
  - Uses Debian package installation, configures Jellyfin metrics and logs.

## Features

- **Metric Collection**: Collects system-level metrics (CPU, memory, disk) and application-specific metrics (e.g., Docker containers, Home Assistant, AdGuard, Jellyfin).
- **Log Collection**: Configures log collection for syslog, Docker, Home Assistant, AdGuard, and Jellyfin.
- **APM (Tracing)**: Enables APM for supported systems (requires manual application instrumentation for full tracing).
- **Alerts**: Configures alerts for high resource usage and service failures via the Datadog API.
- **Secure API Key Handling**: Prompts for the Datadog API key at runtime to avoid hardcoding sensitive information.
- **Error Handling and Logging**: Logs all actions to `/tmp/datadog_install_YYYY-MM-DD_HH-MM-SS.log` for troubleshooting.

## Prerequisites

- **Root Access**: The script must be run as root (e.g., via `sudo`).
- **Internet Access**: All systems must have internet access to download the Datadog Agent and communicate with `datadoghq.com`.
- **Dependencies**:
  - `bash`, `curl` (required for all systems).
  - `jq` (recommended for alert configuration via Datadog API).
  - System-specific tools: `opkg` (OpenWRT), `apt-get` (Debian/Ubuntu), `apk` (Alpine), `docker` (Home Assistant, Docker Host).
- **Datadog Account**: A Datadog account with an API key (available from Datadog UI).
- **System Hostnames**: Each system must have the correct hostname set:
  - `router`, `proxmox`, `adguard-home`, `docker-host`, `home-assistant`, `jellyfin`.
- **Placeholder Values**:
  - Proxmox: Replace `REPLACE_WITH_YOUR_PASSWORD` with your Proxmox API password.
  - Home Assistant: Replace `REPLACE_WITH_YOUR_HA_TOKEN` with your Home Assistant long-lived access token (from **Settings &gt; General &gt; Long-Lived Access Token**).

## Installation

1. **Clone or Download the Repository**:

   ```bash
   git clone https://github.com/your-repo/datadog-install.git
   cd datadog-install
   ```

2. **Edit Placeholder Values**:

   - Open `datadog_install.sh` in a text editor.
   - Replace `REPLACE_WITH_YOUR_PASSWORD` with your Proxmox API password.
   - Replace `REPLACE_WITH_YOUR_HA_TOKEN` with your Home Assistant token.

3. **Copy the Script to Each System**:

   - Transfer `datadog_install.sh` to each system (e.g., via SCP, USB, or direct download).

   - Alternatively, download directly on each system:

     ```bash
     curl -L https://raw.githubusercontent.com/your-repo/datadog-install/main/datadog_install.sh -o datadog_install.sh
     ```

4. **Run the Script on Each System**:

   - Ensure the script is executable:

     ```bash
     chmod +x datadog_install.sh
     ```

   - Run the script as root, entering your Datadog API key when prompted:

     ```bash
     sudo bash datadog_install.sh
     ```

5. **Verify Installation**:

   - Check the log file (e.g., `/tmp/datadog_install_YYYY-MM-DD_HH-MM-SS.log`) for errors.
   - Verify the Datadog Agent is running:
     - Debian/Ubuntu: `systemctl status datadog-agent`
     - Alpine: `rc-service datadog-agent status`
     - Home Assistant: `docker ps | grep dd-agent`
     - OpenWRT: `pgrep snmpd`
   - Visit the Datadog UI to confirm metrics (e.g., `system.cpu.usage`, `docker.containers.running`, `homeassistant.up`).
   - Check logs in Datadog Logs for syslog, Docker, Home Assistant, etc.
   - Verify alerts in Datadog Monitors.

## Configuration Details

- **Datadog Site**: Configured for `datadoghq.com`.
- **Metrics**:
  - System: CPU, memory, disk usage, network I/O.
  - Application: Docker container metrics, Home Assistant sensor data, AdGuard query stats, Jellyfin health checks, router SNMP metrics.
- **Logs**:
  - Syslog (Proxmox, OpenWRT), Docker container logs, Home Assistant (`/config/home-assistant.log`), AdGuard (`/var/log/adguardhome.log`), Jellyfin (`/var/log/jellyfin/*.log`).
- **APM**:
  - Enabled on Proxmox, AdGuard, Docker Host, Home Assistant, and Jellyfin.
  - Requires manual instrumentation for full tracing (e.g., `dd-trace` for Python/Node.js, `dd-trace-dotnet` for .NET). See Datadog Tracing Setup.
- **Alerts**:
  - Configured for high CPU/memory usage, disk full, service failures, and container downtime.
  - Requires `curl` and `jq` for API-based alert setup; otherwise, configure manually in Datadog UI.

## Troubleshooting

- **Installation Fails**:
  - Check the log file for specific errors.
  - Ensure internet connectivity: `ping datadoghq.com`.
  - Verify hostname matches expected values: `hostname`.
  - Confirm root privileges: `id -u`.
- **Agent Not Running**:
  - Debian/Ubuntu: Check `journalctl -u datadog-agent`.
  - Alpine: Check `/opt/datadog-agent/logs/`.
  - Home Assistant: Check `docker logs dd-agent`.
- **Metrics/Logs Missing**:
  - Verify API key in Datadog UI.
  - Check configuration files in `/etc/datadog-agent/conf.d/`.
  - Ensure log file paths are correct (e.g., `/var/log/adguardhome.log`).
- **Alerts Not Working**:
  - Install `jq`: `apt-get install jq` (Debian/Ubuntu) or `apk add jq` (Alpine).
  - Configure alerts manually in Datadog Monitors.
- **OpenWRT Issues**:
  - Ensure `opkg` is functional: `opkg update`.
  - Verify SNMP: `netstat -ul | grep 161`.

## Notes

- **Docker Host**: The script generates a `docker-compose.yml` with Datadog labels for containers (Sonarr, Prowlarr, etc.). Back up your existing `docker-compose.yml` before running.
- **APM**: Full tracing requires application-specific setup (e.g., adding `dd-trace` to Home Assistant or Jellyfin). Refer to Datadog documentation.
- **Security**: The API key is not stored in the script, ensuring safety for public repositories.
- **Custom Paths**: Adjust log file paths in configuration files if your setup differs (e.g., AdGuard or Jellyfin log locations).

## Contributing

Contributions are welcome! Please submit issues or pull requests to the GitHub repository.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## References

- Datadog Agent Documentation
- Datadog Integrations
- Datadog Tracing Setup
- Datadog Network Device Monitoring
