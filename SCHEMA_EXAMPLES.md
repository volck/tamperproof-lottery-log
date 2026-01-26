# Lottery Event Log - Schema Examples

This document provides examples for different event codes based on the log-schema.json.

## Basic Event (Code 0-106)

```bash
# System initialization
./lottery-tlog add-draw --seqno 1 --ip "192.168.1.100" \
  --code 100 --text "System started" --severity "info"
```

## Remote Event (Code 200, 201, 320, 321)

```bash
# Remote connection
./lottery-tlog add-draw --seqno 2 --ip "192.168.1.100" \
  --code 200 --text "Connection established" \
  --remote-ip "10.0.0.50" --severity "info"
```

## Draw Event with Values (Code 300, 330)

JSON file method (recommended for complex events):

```json
{
    "timestamp": "2026-01-21T12:00:00Z",
    "seqno": 3,
    "ip": "192.168.1.100",
    "severity": "info",
    "message": {
        "code": 300,
        "text": "Random values generated",
        "remote_ip": "10.0.0.50",
        "game": 1,
        "draw": 100,
        "subdraw": 1,
        "values": [42, 17, 89, 3, 56]
    },
    "mac": "calculated_mac_here"
}
```

```bash
./lottery-tlog add-draw --json-file draw-300.json
```

## Draw Event with String (Code 301)

```json
{
    "timestamp": "2026-01-21T12:00:00Z",
    "seqno": 4,
    "ip": "192.168.1.100",
    "severity": "info",
    "message": {
        "code": 301,
        "text": "String parameter provided",
        "remote_ip": "10.0.0.50",
        "game": 1,
        "draw": 100,
        "subdraw": 1,
        "string": "some_parameter_value"
    },
    "mac": "calculated_mac_here"
}
```

## Draw Event with Parameters (Code 302)

```json
{
    "timestamp": "2026-01-21T12:00:00Z",
    "seqno": 5,
    "ip": "192.168.1.100",
    "severity": "info",
    "message": {
        "code": 302,
        "text": "Draw parameters configured",
        "remote_ip": "10.0.0.50",
        "game": 1,
        "draw": 100,
        "subdraw": 1,
        "parameters": {
            "low_bound": 1,
            "high_bound": 100,
            "put_back": false,
            "use_distribution": true,
            "distribution": [10, 20, 30, 25, 15]
        }
    },
    "mac": "calculated_mac_here"
}
```

## Integrity Check Event (Code 303)

```json
{
    "timestamp": "2026-01-21T12:00:00Z",
    "seqno": 6,
    "ip": "192.168.1.100",
    "severity": "info",
    "message": {
        "code": 303,
        "text": "Binary and config integrity verified",
        "remote_ip": "10.0.0.50",
        "checks": {
            "binary_checksum": "sha256:abc123...",
            "binary_timestamp": "2026-01-20T10:00:00Z",
            "config_filename": "config.yaml",
            "config_timestamp": "2026-01-20T09:00:00Z"
        }
    },
    "mac": "calculated_mac_here"
}
```

## Result Event (Code 305)

```json
{
    "timestamp": "2026-01-21T12:00:00Z",
    "seqno": 7,
    "ip": "192.168.1.100",
    "severity": "info",
    "message": {
        "code": 305,
        "text": "Draw results published",
        "remote_ip": "10.0.0.50",
        "game": 1,
        "draw": 100,
        "subdraw": 1,
        "values": [7, 14, 21, 35, 42]
    },
    "mac": "calculated_mac_here"
}
```

## Game Control Events (Code 306, 308)

```json
{
    "timestamp": "2026-01-21T12:00:00Z",
    "seqno": 8,
    "ip": "192.168.1.100",
    "severity": "info",
    "message": {
        "code": 306,
        "text": "Game started",
        "remote_ip": "10.0.0.50",
        "game": 1,
        "draw": 101,
        "subdraw": 1
    },
    "mac": "calculated_mac_here"
}
```

## Usage Examples

### Add from JSON file
```bash
./lottery-tlog add-draw --json-file event.json
```

### Add from command line (simple events)
```bash
./lottery-tlog add-draw --seqno 10 --ip "192.168.1.100" \
  --code 101 --text "System ready" \
  --severity "info"
```

### Add with game properties
```bash
./lottery-tlog add-draw --seqno 11 --ip "192.168.1.100" \
  --code 306 --text "Game started" \
  --remote-ip "10.0.0.50" \
  --game 1 --draw 101 --subdraw 1 \
  --severity "info"
```

### List events
```bash
./lottery-tlog list
./lottery-tlog list --verbose
```

### Verify integrity
```bash
./lottery-tlog verify
```

### Check status
```bash
./lottery-tlog status
```

## Notes

- **MAC Field**: The Message Authentication Code is automatically generated using HMAC-SHA256
- **Timestamp**: Auto-generated if not provided in JSON
- **Severity**: Typically "info", "warning", or "error"
- **Game Properties**: Required for codes 300-308 (except 303)
- **Values Array**: Used in codes 300, 305, 330 for random number results
