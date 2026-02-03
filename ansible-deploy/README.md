# Ansible Deployment for Lottery Transparency Log

This Ansible playbook deploys the lottery transparency log server to multiple servers with mTLS authentication for secure inter-server communication.

## Overview

- **Authentication**: mTLS (mutual TLS with client certificates)
- **Backend**: File-based storage (can be changed to Oracle)
- **Witnesses**: Servers cross-verify each other using mTLS

## Prerequisites

1. **Ansible** installed on control machine (`sudo apt install ansible` or `pip install ansible`)
2. **SSH access** to target servers with sudo privileges
3. **Target servers** running Ubuntu/Debian or RHEL/CentOS

## Quick Start

### 1. Configure Inventory

Edit `inventory/hosts.yml` to define your servers:

```yaml
all:
  children:
    lottery_servers:
      hosts:
        lottery1:
          ansible_host: 192.168.1.10
          lottery_port: 8443
          is_primary: true
        lottery2:
          ansible_host: 192.168.1.11
          lottery_port: 8443
        lottery3:
          ansible_host: 192.168.1.12
          lottery_port: 8443
```

### 2. Generate Certificates

```bash
task certs
```

This creates a CA and certificates for all servers in `certs/`.

### 3. Deploy Application

```bash
task deploy
```

This will:
- Copy the binary to each server
- Install certificates
- Configure each server
- Set up systemd service
- Start the service

### 4. Verify Deployment

```bash
task verify
```

## Architecture

- **Primary Server**: Accepts lottery draw submissions (admin role)
- **Witness Servers**: All servers witness and cross-verify tree states
- **mTLS**: All servers authenticate using client certificates

## Manual Operations

Use `task` commands for common operations:

```bash
task restart  # Restart all services
task stop     # Stop all services  
task logs     # View logs from all servers
task status   # Check service status
task clean    # Stop and remove deployment
```

Or use Ansible directly:

### Start/Stop Services

```bash
# Start all servers
ansible lottery_servers -m systemd -a "name=lottery-tlog state=started" --become

# Stop all servers
ansible lottery_servers -m systemd -a "name=lottery-tlog state=stopped" --become

# Restart all servers
ansible lottery_servers -m systemd -a "name=lottery-tlog state=restarted" --become
```

### Check Status

```bash
ansible lottery_servers -m shell -a "systemctl status lottery-tlog" --become
```

### View Logs

```bash
ansible lottery_servers -m shell -a "journalctl -u lottery-tlog -n 50 --no-pager" --become
```

## Files Structure

```
ansible-deploy/
├── README.md
├── ansible.cfg
├── Taskfile.yml
├── inventory/
│   └── hosts.yml
├── playbooks/
│   ├── generate-certs.yml
│   ├── deploy.yml
│   └── verify.yml
├── roles/
│   ├── certificates/
│   │   ├── tasks/
│   │   └── templates/
│   └── lottery-server/
│       ├── tasks/
│       ├── templates/
│       └── handlers/
└── certs/  (generated)
```

## Configuration

Each server gets:
- Unique server certificate for TLS
- CA certificate to verify peers
- Config file with mTLS authentication
- Systemd service for automatic startup
- Peer list for witness cross-checking

## Security Notes

- Keep `certs/ca-key.pem` secure - it signs all certificates
- Rotate certificates regularly (certificates valid for 365 days)
- Use firewall rules to restrict access to port 8443
- Store secrets in Ansible Vault for production
