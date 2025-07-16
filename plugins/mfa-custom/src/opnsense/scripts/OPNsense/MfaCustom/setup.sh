#!/bin/sh
# =============================================================================
# MFA Custom Setup Script – OPNsense Plugin
# This script installs (or removes with --revert) the login patch and the
# MFA enforcement patch that redirects users to the MFA page post-login.
# =============================================================================

USER=root
GROUP=wheel
PERMS=0755

LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/mfacustom.log"

PATCH_LOGIN="/usr/local/opnsense/scripts/OPNsense/MfaCustom/login_mfa.patch"
PATCH_ENFORCER="/usr/local/opnsense/scripts/OPNsense/MfaCustom/mfa_enforcer.patch"

LOGIN_CONTROLLER="/usr/local/opnsense/mvc/app/library/OPNsense/Auth/Local.php"
INDEX_CONTROLLER="/usr/local/opnsense/mvc/app/controllers/OPNsense/Base/IndexController.php"

# -----------------------------------------------------------------------------
# Check for revert flag
# -----------------------------------------------------------------------------
if [ "$1" = "--revert" ]; then
  echo "[*] Reverting MFA Custom plugin patches..."

  # Remove login patch
  if grep -q 'mfa_pending' "$LOGIN_CONTROLLER"; then
    patch -R "$LOGIN_CONTROLLER" "$PATCH_LOGIN" && echo "[✓] Login patch reverted."
  else
    echo "[i] Login patch not found; nothing to revert."
  fi

  # Remove enforcement patch
  if grep -q 'beforeExecuteRoute' "$INDEX_CONTROLLER"; then
    patch -R "$INDEX_CONTROLLER" "$PATCH_ENFORCER" && echo "[✓] Enforcer patch reverted."
  else
    echo "[i] Enforcer patch not found; nothing to revert."
  fi

  exit 0
fi

# -----------------------------------------------------------------------------
# Ensure audit log directory and file exist
# -----------------------------------------------------------------------------
echo "[*] Setting up audit log..."
if [ ! -d "$LOG_DIR" ]; then
  mkdir -p "$LOG_DIR"
  chown -R ${USER}:${GROUP} "$LOG_DIR"
  chmod ${PERMS} "$LOG_DIR"
  echo "[✓] Created directory $LOG_DIR."
else
  echo "[i] Audit log directory already exists."
fi

if [ ! -f "$LOG_FILE" ]; then
  touch "$LOG_FILE"
  chown ${USER}:${GROUP} "$LOG_FILE"
  chmod 644 "$LOG_FILE"
  echo "[✓] Created audit log file at $LOG_FILE."
else
  echo "[i] Audit log file already exists."
fi

# -----------------------------------------------------------------------------
# Apply login MFA patch if needed
# -----------------------------------------------------------------------------
echo "[*] Applying MFA login patch..."
if grep -q 'mfa_pending' "$LOGIN_CONTROLLER"; then
  echo "[✓] Login patch already applied."
else
  patch "$LOGIN_CONTROLLER" "$PATCH_LOGIN" && echo "[+] Login patch applied successfully."
fi

# -----------------------------------------------------------------------------
# Apply global MFA enforcement patch if needed
# -----------------------------------------------------------------------------
echo "[*] Applying MFA enforcer patch..."
if grep -q 'beforeExecuteRoute' "$INDEX_CONTROLLER"; then
  echo "[✓] Enforcer patch already applied."
else
  patch "$INDEX_CONTROLLER" "$PATCH_ENFORCER" && echo "[+] Enforcer patch applied successfully."
fi

echo "[✓] MFA Custom plugin setup completed."
