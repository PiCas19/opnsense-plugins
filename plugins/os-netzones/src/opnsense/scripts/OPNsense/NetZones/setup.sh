#!/bin/sh

# NetZones Setup Script
#
# This script sets up the directory structure, log files, and statistics file for the
# OPNsense NetZones module. It includes comprehensive error checking and permission
# management to ensure the environment is properly configured for the NetZones service.
# The script aligns with the OPNsense ecosystem and integrates with the NetZones Python
# scripts for policy evaluation and logging.
#
# Author: [Not specified]
# Version: 1.0.0
#

# Print initial setup message
echo "[*] Setting up NetZones directories and files..."

# Create configuration directory
echo "[*] Creating configuration directory..."
mkdir -p /usr/local/etc/netzones
if [ $? -eq 0 ]; then
    # Success: Directory created or already exists
    echo "    ✓ Created /usr/local/etc/netzones"
else
    # Failure: Unable to create configuration directory
    echo "    ✗ Failed to create /usr/local/etc/netzones"
    exit 1
fi

# Create runtime directory for PID and stats
echo "[*] Creating runtime directory..."
mkdir -p /var/run
if [ $? -eq 0 ]; then
    # Success: Runtime directory exists or was created
    echo "    ✓ Runtime directory ready"
else
    # Failure: Unable to ensure runtime directory exists
    echo "    ✗ Failed to ensure /var/run exists"
fi

# Create log directory structure
echo "[*] Creating log files..."

# Create main decision log for NetZones policy decisions
touch /var/log/netzones_decisions.log
if [ $? -eq 0 ]; then
    # Set ownership and permissions for decision log
    chown root:wheel /var/log/netzones_decisions.log
    chmod 640 /var/log/netzones_decisions.log
    echo "    ✓ Created /var/log/netzones_decisions.log"
else
    # Failure: Unable to create decision log
    echo "    ✗ Failed to create decision log"
    exit 1
fi

# Create service log for daemon output
touch /var/log/netzones.log
if [ $? -eq 0 ]; then
    # Set ownership and permissions for service log
    chown root:wheel /var/log/netzones.log
    chmod 640 /var/log/netzones.log
    echo "    ✓ Created /var/log/netzones.log"
else
    # Failure: Unable to create service log
    echo "    ✗ Failed to create service log"
fi

# Create debug logs directory for troubleshooting
mkdir -p /tmp/netzones
if [ $? -eq 0 ]; then
    # Set permissions for debug directory
    chmod 755 /tmp/netzones
    echo "    ✓ Created /tmp/netzones debug directory"
else
    # Failure: Unable to create debug directory
    echo "    ✗ Failed to create debug directory"
fi

# Create debug log files used by the NetZones daemon
touch /tmp/netzones_debug.log /tmp/netzones_stdout.log /tmp/netzones_stderr.log
if [ $? -eq 0 ]; then
    # Set permissions for debug log files
    chmod 644 /tmp/netzones_debug.log /tmp/netzones_stdout.log /tmp/netzones_stderr.log
    echo "    ✓ Created daemon debug logs"
else
    # Failure: Unable to create debug log files
    echo "    ✗ Failed to create daemon debug logs"
fi

# Create statistics file with initial content
echo "[*] Initializing statistics file..."
cat > /var/run/netzones_stats.json << 'EOF'
{
  "service_running": false,
  "uptime": 0,
  "requests_processed": 0,
  "decisions_allow": 0,
  "decisions_deny": 0,
  "decisions_block": 0,
  "cache_hits": 0,
  "cache_misses": 0,
  "last_updated": 0
}
EOF

if [ $? -eq 0 ]; then
    # Set ownership and permissions for statistics file
    chown root:wheel /var/run/netzones_stats.json
    chmod 644 /var/run/netzones_stats.json
    echo "    ✓ Initialized /var/run/netzones_stats.json"
else
    # Failure: Unable to create statistics file
    echo "    ✗ Failed to create stats file"
fi

# Create cache directory for configuration caching
echo "[*] Setting up cache directory..."
mkdir -p /tmp/netzones_cache
if [ $? -eq 0 ]; then
    # Set permissions for cache directory
    chmod 755 /tmp/netzones_cache
    echo "    ✓ Created cache directory"
else
    # Failure: Unable to create cache directory
    echo "    ✗ Failed to create cache directory"
fi

# Set proper permissions on main configuration directory
echo "[*] Setting directory permissions..."
chown -R root:wheel /usr/local/etc/netzones
chmod 755 /usr/local/etc/netzones

# Verify setup integrity
echo "[*] Verifying setup..."
ERRORS=0

# Check existence of required directories
for dir in "/usr/local/etc/netzones" "/var/run" "/tmp/netzones" "/tmp/netzones_cache"; do
    if [ ! -d "$dir" ]; then
        # Directory missing, increment error count
        echo "    ✗ Missing directory: $dir"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check existence of required files
for file in "/var/log/netzones_decisions.log" "/var/log/netzones.log" "/var/run/netzones_stats.json"; do
    if [ ! -f "$file" ]; then
        # File missing, increment error count
        echo "    ✗ Missing file: $file"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check if /var/run is writable for socket creation
if [ ! -w "/var/run" ]; then
    # /var/run not writable, increment error count
    echo "    ✗ /var/run is not writable"
    ERRORS=$((ERRORS + 1))
fi

# Summarize setup results
if [ $ERRORS -eq 0 ]; then
    # Success: All checks passed
    echo "    ✓ All checks passed"
    echo ""
    echo "[✓] NetZones setup completed successfully!"
    echo ""
    echo "Files created:"
    echo "  - Configuration: /usr/local/etc/netzones/"
    echo "  - Decision log:  /var/log/netzones_decisions.log"
    echo "  - Service log:   /var/log/netzones.log"
    echo "  - Statistics:    /var/run/netzones_stats.json"
    echo "  - Debug logs:    /tmp/netzones_*.log"
    echo "  - Cache:         /tmp/netzones_cache/"
    echo ""
    echo "Ready to start NetZones service!"
else
    # Failure: Report errors and exit
    echo ""
    echo "[✗] Setup completed with $ERRORS error(s). Please review the output above."
    exit 1
fi