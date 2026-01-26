# Build Instructions

This document explains how to build the lottery transparency log with and without Oracle support.

## Quick Start

### Default Build (File-Based Storage Only)

No external dependencies required:

```bash
go build -o lottery-tlog
```

This builds the application with:
- ✅ File-based storage backend
- ✅ All Merkle tree functionality
- ✅ All CLI commands
- ❌ Oracle 19c blockchain support

## Build with Oracle Support

If you want to use Oracle 19c blockchain tables, you need:

1. **Oracle Instant Client** installed on your system
2. Build with the `oracle` tag

### Step 1: Install Oracle Instant Client

#### Linux (RPM-based - RHEL/CentOS/Fedora)

```bash
# Download from Oracle website or use wget
wget https://download.oracle.com/otn_software/linux/instantclient/2340000/oracle-instantclient-basic-23.4.0.24.05-1.x86_64.rpm
wget https://download.oracle.com/otn_software/linux/instantclient/2340000/oracle-instantclient-devel-23.4.0.24.05-1.x86_64.rpm

# Install
sudo rpm -ivh oracle-instantclient-basic-*.rpm
sudo rpm -ivh oracle-instantclient-devel-*.rpm

# Set environment variables (add to ~/.bashrc)
export LD_LIBRARY_PATH=/usr/lib/oracle/23/client64/lib:$LD_LIBRARY_PATH
export PATH=/usr/lib/oracle/23/client64/bin:$PATH
```

#### Linux (DEB-based - Debian/Ubuntu)

```bash
# Download and convert RPM to DEB
wget https://download.oracle.com/otn_software/linux/instantclient/2340000/oracle-instantclient-basic-23.4.0.24.05-1.x86_64.rpm
alien --to-deb oracle-instantclient-basic-*.rpm
sudo dpkg -i oracle-instantclient-basic_*.deb

# Set environment
export LD_LIBRARY_PATH=/usr/lib/oracle/23/client64/lib:$LD_LIBRARY_PATH
```

#### macOS

```bash
# Download from Oracle website
# Install to /usr/local/lib or ~/lib

# Set environment
export DYLD_LIBRARY_PATH=/path/to/instantclient:$DYLD_LIBRARY_PATH
```

#### Windows

```bash
# Download Oracle Instant Client Basic and SDK
# Extract to C:\oracle\instantclient_XX_X

# Add to PATH
set PATH=C:\oracle\instantclient_XX_X;%PATH%
```

### Step 2: Build with Oracle Tag

```bash
# Build with Oracle support
go build -tags oracle -o lottery-tlog

# Verify it works
./lottery-tlog --help
```

## Build Tags Explained

This project uses Go build tags to make Oracle support optional:

### File: `oracle/lottery_log.go`
```go
// +build oracle
```
- Only compiled when `-tags oracle` is used
- Contains Oracle-specific database code
- Requires godror package (which needs Oracle client)

### File: `oracle/stub.go`
```go
// +build !oracle
```
- Only compiled when `-tags oracle` is NOT used (default)
- Contains stub implementations that return errors
- No Oracle dependencies required

## Testing Your Build

### Test File-Based Build

```bash
# Build without Oracle
go build -o lottery-tlog

# Should work with file backend
./lottery-tlog status

# Should error with Oracle backend
# Edit config.yaml: storage_backend: "oracle"
./lottery-tlog status
# Error: "Oracle support not compiled in. Build with: go build -tags oracle"
```

### Test Oracle Build

```bash
# Build with Oracle
go build -tags oracle -o lottery-tlog

# Configure Oracle in config.yaml
# storage_backend: "oracle"
# oracle:
#   connection_string: "user/pass@host:port/service"

# Should connect to Oracle
./lottery-tlog status
```

## Cross-Compilation

### File-Based Only (Works Anywhere)

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o lottery-tlog-linux

# macOS
GOOS=darwin GOARCH=amd64 go build -o lottery-tlog-mac

# Windows
GOOS=windows GOARCH=amd64 go build -o lottery-tlog.exe

# ARM64 (e.g., Raspberry Pi, Apple Silicon)
GOOS=linux GOARCH=arm64 go build -o lottery-tlog-arm64
```

### With Oracle Support

Cross-compilation with Oracle requires:
- Target platform's Oracle Instant Client
- CGO enabled
- Proper cross-compilation toolchain

```bash
# Example: Linux AMD64 with Oracle
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags oracle -o lottery-tlog-linux
```

## Troubleshooting

### Error: "undefined: godror.VersionInfo"

**Problem**: Building without Oracle Instant Client installed  
**Solution**: Either install Oracle Instant Client, or build without `-tags oracle`

```bash
# Build without Oracle support (default)
go build -o lottery-tlog
```

### Error: "cannot find -lclntsh"

**Problem**: Oracle libraries not found by linker  
**Solution**: Set LD_LIBRARY_PATH (Linux) or DYLD_LIBRARY_PATH (macOS)

```bash
# Linux
export LD_LIBRARY_PATH=/usr/lib/oracle/XX/client64/lib:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=/path/to/instantclient:$DYLD_LIBRARY_PATH
```

### Error: "Oracle support not compiled in"

**Problem**: Binary built without Oracle tag, but config uses Oracle backend  
**Solution**: Either rebuild with Oracle support, or change config to use file backend

```bash
# Option 1: Rebuild with Oracle
go build -tags oracle -o lottery-tlog

# Option 2: Use file backend
# Edit config.yaml: storage_backend: "file"
```

## Development Workflow

### Recommended Setup

For development without Oracle dependencies:

```bash
# Use file backend by default
# config.yaml:
storage_backend: "file"

# Build and test
go build -o lottery-tlog
./lottery-tlog add-draw --draw-id test --random
./lottery-tlog list
./lottery-tlog verify
```

### Testing Oracle Integration

Only when working on Oracle-specific features:

```bash
# Ensure Oracle Instant Client installed
# Configure Oracle connection
# Build with Oracle tag
go build -tags oracle -o lottery-tlog

# Test Oracle-specific features
./lottery-tlog status  # Should show Oracle blockchain info
```

## CI/CD Considerations

### GitHub Actions Example

```yaml
jobs:
  build-file-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.23'
      - run: go build -o lottery-tlog
      - run: ./lottery-tlog --help

  build-oracle:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Oracle Instant Client
        run: |
          wget https://download.oracle.com/...
          sudo rpm -ivh oracle-instantclient-*.rpm
          export LD_LIBRARY_PATH=/usr/lib/oracle/23/client64/lib
      - uses: actions/setup-go@v4
        with:
          go-version: '1.23'
      - run: go build -tags oracle -o lottery-tlog
```

## Release Artifacts

When distributing binaries:

1. **Standard Release** (File-based only):
   ```bash
   go build -o lottery-tlog-v1.0.0-linux-amd64
   ```
   - Works on any system
   - No dependencies
   - Smaller binary

2. **Oracle Release** (With Oracle support):
   ```bash
   go build -tags oracle -o lottery-tlog-oracle-v1.0.0-linux-amd64
   ```
   - Requires Oracle Instant Client on target system
   - Larger binary
   - Include Oracle setup instructions

## Summary

- **Default build**: File-based storage, no Oracle dependencies
- **Oracle build**: Use `-tags oracle`, requires Oracle Instant Client
- **Production**: Choose backend based on requirements
  - File: Simple, portable, good for small deployments
  - Oracle: Enterprise-grade, blockchain signatures, immutability
