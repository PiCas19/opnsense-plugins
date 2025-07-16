#!/bin/sh

# NetZones Setup Script
# Enhanced version with error checking and complete directory structure

echo "[*] Setting up NetZones directories and files..."

# Create configuration directory
echo "[*] Creating configuration directory..."
mkdir -p /usr/local/etc/netzones
if [ $? -eq 0 ]; then
    echo "    ✓ Created /usr/local/etc/netzones"
else
    echo "    ✗ Failed to create /usr/local/etc/netzones"
    exit 1
fi

# Create runtime directory for PID and stats
echo "[*] Creating runtime directory..."
mkdir -p /var/run
if [ $? -eq 0 ]; then
    echo "    ✓ Runtime directory ready"
else
    echo "    ✗ Failed to ensure /var/run exists"
fi

# Create log directory structure
echo "[*] Creating log files..."

# Main decision log
touch /var/log/netzones_decisions.log
if [ $? -eq 0 ]; then
    chown root:wheel /var/log/netzones_decisions.log
    chmod 640 /var/log/netzones_decisions.log
    echo "    ✓ Created /var/log/netzones_decisions.log"
else
    echo "    ✗ Failed to create decision log"
    exit 1
fi

# Service log for daemon output
touch /var/log/netzones.log
if [ $? -eq 0 ]; then
    chown root:wheel /var/log/netzones.log
    chmod 640 /var/log/netzones.log
    echo "    ✓ Created /var/log/netzones.log"
else
    echo "    ✗ Failed to create service log"
fi

# Debug logs directory for troubleshooting
mkdir -p /tmp/netzones
if [ $? -eq 0 ]; then
    chmod 755 /tmp/netzones
    echo "    ✓ Created /tmp/netzones debug directory"
else
    echo "    ✗ Failed to create debug directory"
fi

# Ensure debug logs exist (used by daemon)
touch /tmp/netzones_debug.log /tmp/netzones_stdout.log /tmp/netzones_stderr.log
if [ $? -eq 0 ]; then
    chmod 644 /tmp/netzones_debug.log /tmp/netzones_stdout.log /tmp/netzones_stderr.log
    echo "    ✓ Created daemon debug logs"
else
    echo "    ✗ Failed to create daemon debug logs"
fi

# Create stats file with initial content
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
    chown root:wheel /var/run/netzones_stats.json
    chmod 644 /var/run/netzones_stats.json
    echo "    ✓ Initialized /var/run/netzones_stats.json"
else
    echo "    ✗ Failed to create stats file"
fi

# Create cache directory
echo "[*] Setting up cache directory..."
mkdir -p /tmp/netzones_cache
if [ $? -eq 0 ]; then
    chmod 755 /tmp/netzones_cache
    echo "    ✓ Created cache directory"
else
    echo "    ✗ Failed to create cache directory"
fi

# Set proper permissions on main directory
echo "[*] Setting directory permissions..."
chown -R root:wheel /usr/local/etc/netzones
chmod 755 /usr/local/etc/netzones

# Verify setup
echo "[*] Verifying setup..."
ERRORS=0

# Check directories
for dir in "/usr/local/etc/netzones" "/var/run" "/tmp/netzones" "/tmp/netzones_cache"; do
    if [ ! -d "$dir" ]; then
        echo "    ✗ Missing directory: $dir"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check files
for file in "/var/log/netzones_decisions.log" "/var/log/netzones.log" "/var/run/netzones_stats.json"; do
    if [ ! -f "$file" ]; then
        echo "    ✗ Missing file: $file"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check socket directory permissions
if [ ! -w "/var/run" ]; then
    echo "    ✗ /var/run is not writable"
    ERRORS=$((ERRORS + 1))
fi

if [ $ERRORS -eq 0 ]; then
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
    echo ""
    echo "[✗] Setup completed with $ERRORS error(s)"
    echo "Please check the errors above and fix manually if needed."
    exit 1
fi