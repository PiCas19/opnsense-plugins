#!/bin/sh

echo "=== SiemLogger Debug Script ==="
echo "Data/ora: $(date)"
echo

# 1. Controlla se i file esistono
echo "=== Controllo Files ==="
FILES_TO_CHECK="
/usr/local/bin/python3.11
/usr/local/opnsense/scripts/OPNsense/SiemLogger/siemlogger_engine.py
/usr/local/opnsense/scripts/OPNsense/SiemLogger/settings_logger.py
/usr/local/opnsense/scripts/OPNsense/SiemLogger/export_events.py
/usr/local/etc/rc.d/siemlogger
/usr/local/etc/siemlogger/config.json
"

for file in $FILES_TO_CHECK; do
    if [ -f "$file" ]; then
        echo "✓ $file ($(ls -la "$file" | awk '{print $1, $3, $4}'))"
    else
        echo "✗ $file (MANCANTE)"
    fi
done

# 2. Controlla le directory
echo
echo "=== Controllo Directories ==="
DIRS_TO_CHECK="
/var/log/siemlogger
/usr/local/etc/siemlogger
/var/db/siemlogger
/var/run
"

for dir in $DIRS_TO_CHECK; do
    if [ -d "$dir" ]; then
        echo "✓ $dir ($(ls -ld "$dir" | awk '{print $1, $3, $4}'))"
    else
        echo "✗ $dir (MANCANTE)"
    fi
done

# 3. Testa Python e imports
echo
echo "=== Test Python e Moduli ==="
if [ -f /usr/local/bin/python3.11 ]; then
    echo "Python version:"
    /usr/local/bin/python3.11 --version
    
    echo
    echo "Test import settings_logger:"
    cd /usr/local/opnsense/scripts/OPNsense/SiemLogger/
    /usr/local/bin/python3.11 -c "
try:
    from settings_logger import load_config
    print('✓ settings_logger import OK')
    config = load_config()
    print('✓ load_config() OK')
    print('Config sections:', list(config.keys()) if config else 'None')
except Exception as e:
    print('✗ settings_logger error:', e)
" 2>&1

    echo
    echo "Test import export_events:"
    /usr/local/bin/python3.11 -c "
try:
    from export_events import export_to_siem, load_config
    print('✓ export_events import OK')
except Exception as e:
    print('✗ export_events error:', e)
" 2>&1

else
    echo "✗ Python3.11 non trovato"
fi

# 4. Controlla il daemon script
echo
echo "=== Test Daemon Script ==="
if [ -f /usr/local/etc/rc.d/siemlogger ]; then
    echo "Daemon script esiste, test syntax..."
    sh -n /usr/local/etc/rc.d/siemlogger && echo "✓ Syntax OK" || echo "✗ Syntax ERROR"
    
    echo "Permessi daemon script:"
    ls -la /usr/local/etc/rc.d/siemlogger
else
    echo "✗ Daemon script mancante"
fi

# 5. Controlla i log di errore
echo
echo "=== Log Recenti ==="
if [ -f /var/log/siemlogger/service.log ]; then
    echo "Ultimi 10 errori da service.log:"
    tail -10 /var/log/siemlogger/service.log
else
    echo "service.log non esiste ancora"
fi

if [ -f /var/log/siemlogger/stderr.log ]; then
    echo
    echo "Ultimi errori da stderr.log:"
    tail -10 /var/log/siemlogger/stderr.log
else
    echo "stderr.log non esiste ancora"
fi

# 6. Test configurazione OPNsense
echo
echo "=== Test Configurazione OPNsense ==="
if [ -f /conf/config.xml ]; then
    if grep -q "SiemLogger" /conf/config.xml; then
        echo "✓ Sezione SiemLogger trovata in config.xml"
        echo "Configurazione SiemLogger:"
        grep -A 20 -B 5 "SiemLogger" /conf/config.xml | head -30
    else
        echo "✗ Sezione SiemLogger non trovata in config.xml"
    fi
else
    echo "✗ /conf/config.xml non trovato"
fi

# 7. Test manuale dell'engine
echo
echo "=== Test Manuale Engine ==="
if [ -f /usr/local/opnsense/scripts/OPNsense/SiemLogger/siemlogger_engine.py ]; then
    echo "Test diretto dell'engine (timeout 10s)..."
    cd /usr/local/opnsense/scripts/OPNsense/SiemLogger/
    timeout 10 /usr/local/bin/python3.11 siemlogger_engine.py test 2>&1 || echo "Test completato/timeout"
else
    echo "✗ Engine script non trovato"
fi

# 8. Controlla processi
echo
echo "=== Processi Attivi ==="
ps aux | grep -E "(siemlogger|python.*siem)" | grep -v grep

# 9. Controlla PID file
echo
echo "=== PID File ==="
if [ -f /var/run/siemlogger.pid ]; then
    PID=$(cat /var/run/siemlogger.pid)
    echo "PID file esiste: $PID"
    if kill -0 "$PID" 2>/dev/null; then
        echo "✓ Processo $PID è attivo"
    else
        echo "✗ Processo $PID non è attivo (PID file stale)"
    fi
else
    echo "PID file non esiste"
fi

echo
echo "=== Fine Debug ==="