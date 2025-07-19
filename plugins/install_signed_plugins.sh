#!/bin/sh
###############################################################################
# install_signed_plugins.sh
# --------------------------
# Builds, signs, and installs local OPNsense plugins from source.
# Assumes plugin packages already built in each plugin/work/pkg/*.pkg
###############################################################################

set -e

PLUGIN_DIRS="os-webguard"
REPO_NAME="localrepo"
REPO_BASE="/usr/local/localrepo"
REPO_DIR="${REPO_BASE}/packages"
REPO_ALL="${REPO_DIR}/All"
KEY_PRIV="/usr/local/etc/pkg/priv.key"
KEY_PUB="/usr/local/etc/pkg/pub.key"
PKG_REPO_CONF="/etc/pkg/${REPO_NAME}.conf"
LOG_FILE="/var/log/plugin_installer.log"

AUTO_DISCOVER=false
DRY_RUN=false
CLEAN=false

# --- Parse arguments ---
for arg in "$@"; do
  case "$arg" in
    --auto-discover) AUTO_DISCOVER=true ;;
    --dry-run) DRY_RUN=true ;;
    --clean) CLEAN=true ;;
    --help)
      echo "Usage: $0 [--auto-discover] [--dry-run] [--clean]"
      exit 0 ;;
    *) echo "[ERROR] Unknown option: $arg"; exit 1 ;;
  esac
done

# --- Logging helpers ---
log() {
  echo "$@" | tee -a "$LOG_FILE"
}

run() {
  if [ "$DRY_RUN" = true ]; then
    log "[DRY-RUN] $*"
  else
    "$@"
  fi
}

# --- Check dependencies ---
for cmd in pkg openssl jq; do
  if ! command -v "$cmd" >/dev/null; then
    log "[ERROR] Required command not found: $cmd"
    exit 1
  fi
done

# --- Auto-discover plugin directories if requested ---
if [ "$AUTO_DISCOVER" = true ]; then
  log "[INFO] Auto-discovering plugins..."
  PLUGIN_DIRS=$(find /usr/plugins/security -maxdepth 1 -type d -name "os-*" -exec basename {} \;)
fi

# --- Ensure RSA keys exist ---
if [ ! -f "$KEY_PRIV" ] || [ ! -f "$KEY_PUB" ]; then
  log "[INFO] Generating RSA keys..."
  run mkdir -p "$(dirname "$KEY_PRIV")"
  run openssl genrsa -out "$KEY_PRIV" 4096
  run openssl rsa -in "$KEY_PRIV" -pubout -out "$KEY_PUB"
fi

# --- Prepare local package repo ---
log "[INFO] Preparing repository at $REPO_ALL"
run mkdir -p "$REPO_ALL"
if [ "$CLEAN" = true ]; then
  log "[INFO] Cleaning old packages..."
  run rm -f "$REPO_ALL"/*.pkg || true
fi

# --- Copy .pkg files into repo ---
for plugin in $PLUGIN_DIRS; do
  PLUGIN_PATH="/usr/plugins/security/$plugin"
  META_FILE="$PLUGIN_PATH/meta.json"
  PKG_SRC="$PLUGIN_PATH/work/pkg"

  log "[INFO] Processing $plugin"

  if [ ! -f "$META_FILE" ]; then
    log "[ERROR] Missing meta.json in $plugin"
    continue
  fi

  PKG_ID=$(jq -r .product_id "$META_FILE")
  if [ -z "$PKG_ID" ] || [ "$PKG_ID" = "null" ]; then
    log "[ERROR] Invalid product_id in meta.json"
    continue
  fi

  if [ -d "$PKG_SRC" ] && ls "$PKG_SRC"/*.pkg >/dev/null 2>&1; then
    run cp "$PKG_SRC"/*.pkg "$REPO_ALL/"
  else
    log "[WARN] No package found in $PKG_SRC"
    continue
  fi
done

# --- Sign repository ---
log "[INFO] Signing repository..."
run pkg repo "$REPO_DIR" rsa:"$KEY_PRIV"

# --- Write pkg repo config ---
cat <<EOF | tee "$PKG_REPO_CONF" >/dev/null
${REPO_NAME}: {
  url: "file://${REPO_DIR}",
  mirror_type: "none",
  signature_type: "pubkey",
  pubkey: "${KEY_PUB}",
  enabled: yes
}
EOF

# --- Update and install packages ---
log "[INFO] Updating pkg index..."
run env ASSUME_ALWAYS_YES=yes pkg update -f

for pkg_file in "$REPO_ALL"/*.pkg; do
  PKG_FILENAME=$(basename "$pkg_file")
  case "$PKG_FILENAME" in
    meta.pkg|packagesite.pkg) continue ;;
  esac

  PKG_NAME=$(pkg info -F "$pkg_file" | awk '/^Name/ {print $3}')
  run pkg install -y "$PKG_NAME"
  run pluginctl -r "$PKG_NAME" || log "[WARN] pluginctl failed"
  run service configd restart
  run rm -rf /tmp/opnsense_config_cache/* || true

  # --- Fix script permissions after install ---
  SCRIPTS_DIR="/usr/local/opnsense/scripts/OPNsense/${PKG_NAME#os-}"
  if [ -d "$SCRIPTS_DIR" ]; then
    find "$SCRIPTS_DIR" -type f \( -name "*.sh" -o -name "*.py" \) | while read script; do
      run chmod +x "$script"
      log "[CHMOD] Set executable on $script"
    done
  fi

  # --- Fix daemon script permission ---
  RC_SCRIPT="/usr/local/etc/rc.d/${PKG_NAME#os-}"
  if [ -f "$RC_SCRIPT" ]; then
    run chmod +x "$RC_SCRIPT"
    log "[CHMOD] Set executable on daemon $RC_SCRIPT"
  fi

  # --- Esegui setup.sh se esiste ---
  SETUP_SCRIPT="${SCRIPTS_DIR}/setup.sh"
  if [ -x "$SETUP_SCRIPT" ]; then
    log "[SETUP] Eseguendo $SETUP_SCRIPT"
    run "$SETUP_SCRIPT"
  fi

  # --- Abilita servizio in /etc/rc.conf e avvia ---
  if [ -f "$RC_SCRIPT" ]; then
    SERVICE_NAME="${PKG_NAME#os-}"

    if grep -q "^${SERVICE_NAME}_enable=" /etc/rc.conf; then
      CURRENT_VAL=$(grep "^${SERVICE_NAME}_enable=" /etc/rc.conf | cut -d'"' -f2)
      if [ "$CURRENT_VAL" != "YES" ]; then
        log "[RC] Modifico ${SERVICE_NAME}_enable=YES in /etc/rc.conf"
        run sed -i '' "s/^${SERVICE_NAME}_enable=.*/${SERVICE_NAME}_enable=\"YES\"/" /etc/rc.conf
      else
        log "[RC] ${SERVICE_NAME}_enable è già impostato su YES, non modifico"
      fi
    else
      log "[RC] Aggiungo ${SERVICE_NAME}_enable=\"YES\" in /etc/rc.conf"
      echo "${SERVICE_NAME}_enable=\"YES\"" | tee -a /etc/rc.conf >/dev/null
    fi

    log "[SERVICE] Avvio servizio $SERVICE_NAME"
    run service "$SERVICE_NAME" start || log "[WARN] Impossibile avviare $SERVICE_NAME"
  fi

  # --- Riavvio webserver se necessario ---
  for svc in lighttpd nginx apache24 apache22; do
    if service "$svc" status >/dev/null 2>&1; then
      run service "$svc" restart || log "[WARN] $svc restart failed"
      break
    fi
  done
done

log "[DONE] All plugins installed and repository signed."
log "[INFO] Refresh browser and check OPNsense UI."