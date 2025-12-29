#!/bin/bash
set -euo pipefail
trap 'echo "[ERROR] Script failed at line $LINENO"' ERR

##############################################
# Wazuh Dev/Test Environment Installer
# WARNING: FOR DEVELOPMENT/TESTING ONLY
# - Uses nightly builds
# - Destroys existing data on clean install
# - Uses default configurations
##############################################

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

##############################################
# 0) Require root
##############################################
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  log_error "This script must be run as root"
  exit 1
fi

log_warn "This is a DEVELOPMENT/TESTING installer!"
log_warn "It will DELETE existing Wazuh data on clean install"
echo
read -r -p "Continue? [y/N]: " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || exit 0

##############################################
# 1) Configuration options
##############################################
echo
log_info "Installation Options:"
echo "  1) Quick install (download + clean install all)"
echo "  2) Custom (choose download/install per component)"
echo "  3) Local packages only (no download)"
read -r -p "Choice [1-3]: " INSTALL_MODE

case "$INSTALL_MODE" in
  1)
    DOWNLOAD_PKGS=true
    QUICK_MODE=true
    ;;
  2)
    read -r -p "Download packages? [y/N]: " DOWNLOAD
    [[ "$DOWNLOAD" =~ ^[Yy]$ ]] && DOWNLOAD_PKGS=true || DOWNLOAD_PKGS=false
    QUICK_MODE=false
    ;;
  3)
    DOWNLOAD_PKGS=false
    QUICK_MODE=false
    ;;
  *)
    log_error "Invalid choice"
    exit 1
    ;;
esac

##############################################
# 2) Detect system
##############################################
ARCH_RAW="$(uname -m)"
BASE_URL="https://packages-dev.wazuh.com/nightly-backup"
VERSION="5.0.0"

# Detect package manager
if command -v rpm >/dev/null 2>&1; then
  PKG_TYPE="rpm"
  PKG_MGR="rpm"
  log_info "Detected RPM-based system"
elif command -v dpkg >/dev/null 2>&1; then
  PKG_TYPE="deb"
  PKG_MGR="dpkg"
  log_info "Detected DEB-based system"
else
  log_error "Neither rpm nor dpkg found"
  exit 1
fi

# Normalize architecture
if [[ "$PKG_TYPE" == "rpm" ]]; then
  case "$ARCH_RAW" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)
      log_error "Unsupported architecture for RPM: $ARCH_RAW"
      exit 1
      ;;
  esac
else
  case "$ARCH_RAW" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
      log_error "Unsupported architecture for DEB: $ARCH_RAW"
      exit 1
      ;;
  esac
fi

log_info "Architecture: $ARCH"

##############################################
# 3) Optional local dashboard package
##############################################
DASHBOARD_LOCAL_PKG=""

echo
read -r -p "Install Wazuh Dashboard from a local package next to install-v2.sh? [y/N]: " USE_LOCAL_DASHBOARD
if [[ "$USE_LOCAL_DASHBOARD" =~ ^[Yy]$ ]]; then
  if [[ "$PKG_TYPE" == "rpm" ]]; then
    DASHBOARD_GLOB="$SCRIPT_DIR/wazuh-dashboard*.rpm"
  else
    DASHBOARD_GLOB="$SCRIPT_DIR/wazuh-dashboard*.deb"
  fi

  shopt -s nullglob
  matches=( $DASHBOARD_GLOB )
  shopt -u nullglob

  if [[ ${#matches[@]} -eq 0 ]]; then
    log_error "No local Wazuh Dashboard package found matching: $DASHBOARD_GLOB"
    exit 1
  fi

  for f in "${matches[@]}"; do
    if [[ "$f" == *"$ARCH"* ]]; then
      DASHBOARD_LOCAL_PKG="$f"
      break
    fi
  done
  [[ -z "$DASHBOARD_LOCAL_PKG" ]] && DASHBOARD_LOCAL_PKG="${matches[0]}"

  log_info "Using local Wazuh Dashboard package: $DASHBOARD_LOCAL_PKG"
fi

##############################################
# 4) Package names
##############################################
if [[ "$PKG_TYPE" == "rpm" ]]; then
  INDEXER_PKG="wazuh-indexer-${VERSION}-latest.${ARCH}.rpm"
  MANAGER_PKG="wazuh-manager-${VERSION}-latest.${ARCH}.rpm"
  DASHBOARD_PKG="wazuh-dashboard-${VERSION}-latest.${ARCH}.rpm"
else
  INDEXER_PKG="wazuh-indexer_${VERSION}-latest_${ARCH}.deb"
  MANAGER_PKG="wazuh-manager_${VERSION}-latest_${ARCH}.deb"
  DASHBOARD_PKG="wazuh-dashboard_${VERSION}-latest_${ARCH}.deb"
fi

if [[ -n "$DASHBOARD_LOCAL_PKG" ]]; then
  DASHBOARD_PKG="$DASHBOARD_LOCAL_PKG"
fi

##############################################
# 5) Download functions
##############################################
find_pkg_date() {
  local pkg="$1"
  local i DATE
  
  log_info "Searching for $pkg in recent builds..." >&2
  
  for i in {0..6}; do
    DATE=$(date -u -d "-$i day" +"%Y-%m-%d")
    if curl -s --head --fail "$BASE_URL/$DATE/$pkg" >/dev/null 2>&1; then
      echo "$DATE"
      return 0
    fi
  done
  return 1
}

download_package() {
  local pkg="$1"
  
  if [[ -f "$pkg" ]]; then
    log_info "$pkg already exists locally"
    return 0
  fi
  
  DATE="$(find_pkg_date "$pkg" || true)"
  if [[ -z "${DATE:-}" ]]; then
    log_error "$pkg not found in last 7 days of builds"
    return 1
  fi
  
  log_info "Downloading $pkg from $DATE..."
  
  # Download with progress bar
  if ! curl -L --progress-bar "$BASE_URL/$DATE/$pkg" -o "$pkg"; then
    log_error "Failed to download $pkg"
    rm -f "$pkg"  # Clean up partial download
    return 1
  fi
  
  log_success "Downloaded $pkg"
  return 0
}

if [[ "$DOWNLOAD_PKGS" == true ]]; then
  echo
  log_info "Downloading packages..."
  
  for PKG in "$INDEXER_PKG" "$MANAGER_PKG" "$DASHBOARD_PKG"; do
    if ! download_package "$PKG"; then
      log_error "Download failed. Exiting."
      exit 1
    fi
  done
fi

##############################################
# 6) Installation functions
##############################################
GENERATE_CERTS=false

# Check if component is installed
is_installed() {
  local name="$1"
  
  if [[ "$PKG_TYPE" == "rpm" ]]; then
    rpm -q "$name" >/dev/null 2>&1
  else
    dpkg -l | grep -qE "^ii[[:space:]]+$name([[:space:]]|:)"
  fi
}

# Stop service if running
stop_service() {
  local name="$1"
  
  if systemctl is-active --quiet "$name"; then
    log_info "Stopping $name service..."
    systemctl stop "$name"
    sleep 2
  fi
}

# Clean removal of component
clean_component() {
  local name="$1"
  
  log_warn "Removing $name completely (THIS WILL DELETE ALL DATA)"
  
  stop_service "$name"
  
  if [[ "$PKG_TYPE" == "rpm" ]]; then
    rpm -e --nodeps "$name" 2>/dev/null || true
  else
    apt-get purge -y "$name" 2>/dev/null || true
  fi
  
  # Component-specific cleanup
  case "$name" in
    wazuh-indexer)
      rm -rf /etc/wazuh-indexer /usr/share/wazuh-indexer /var/lib/wazuh-indexer /var/log/wazuh-indexer
      GENERATE_CERTS=true
      ;;
    wazuh-manager)
      rm -rf /var/ossec /etc/ossec* /var/log/ossec*
      ;;
    wazuh-dashboard)
      rm -rf /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard /var/log/wazuh-dashboard
      ;;
  esac
  
  log_success "$name removed completely"
}

# Install package
install_component() {
  local pkg="$1"
  local name="$2"
  local generate_certs="${3:-false}"
  
  log_info "Installing $name from $pkg..."
  
  if [[ "$PKG_TYPE" == "rpm" ]]; then
    if [[ "$generate_certs" == true && "$name" == "wazuh-indexer" ]]; then
      GENERATE_CERTS=true rpm -ivh "$pkg"
    else
      rpm -ivh "$pkg"
    fi
  else
    if [[ "$generate_certs" == true && "$name" == "wazuh-indexer" ]]; then
      GENERATE_CERTS=true dpkg -i "$pkg" || {
        log_info "Fixing dependencies..."
        apt-get -f install -y
        GENERATE_CERTS=true dpkg -i "$pkg"
      }
    else
      dpkg -i "$pkg" || {
        log_info "Fixing dependencies..."
        apt-get -f install -y
        dpkg -i "$pkg"
      }
    fi
  fi
  
  log_success "$name installed"
}

# Main install logic
install_pkg() {
  local pkg="$1"
  local name="$2"
  local action="install"
  
  echo
  echo "========================================="
  log_info "Processing: $name"
  echo "========================================="
  
  if [[ ! -f "$pkg" ]]; then
    log_error "Package file not found: $pkg"
    log_warn "Skipping $name"
    return
  fi
  
  if is_installed "$name"; then
    if [[ "$QUICK_MODE" == true ]]; then
      action="clean"
    else
      log_warn "$name is already installed"
      echo "  [C] Clean install (DELETE all data)"
      echo "  [U] Upgrade (keep data)"
      echo "  [S] Skip"
      read -r -p "Choice [C/U/S]: " choice
      
      case "${choice^^}" in
        C) action="clean" ;;
        U) action="upgrade" ;;
        S) 
          log_info "Skipping $name"
          return 
          ;;
        *) 
          log_info "Invalid choice, skipping"
          return
          ;;
      esac
    fi
  else
    [[ "$name" == "wazuh-indexer" ]] && GENERATE_CERTS=true
  fi
  
  case "$action" in
    clean)
      clean_component "$name"
      [[ "$name" == "wazuh-indexer" ]] && GENERATE_CERTS=true
      install_component "$pkg" "$name" "$GENERATE_CERTS"
      ;;
    upgrade)
      log_info "Upgrading $name..."
      stop_service "$name"
      
      if [[ "$PKG_TYPE" == "rpm" ]]; then
        rpm -Uvh --replacepkgs "$pkg"
      else
        dpkg -i "$pkg" || {
          apt-get -f install -y
          dpkg -i "$pkg"
        }
      fi
      
      log_success "$name upgraded"
      ;;
    install)
      local gen_certs=false
      [[ "$name" == "wazuh-indexer" ]] && gen_certs=true
      install_component "$pkg" "$name" "$gen_certs"
      ;;
  esac
}

##############################################
# 7) Install components
##############################################
install_pkg "$INDEXER_PKG" "wazuh-indexer"
install_pkg "$MANAGER_PKG" "wazuh-manager"
install_pkg "$DASHBOARD_PKG" "wazuh-dashboard"

##############################################
# 8) All in one configuration
##############################################
echo
log_info "Configuring all services..."

systemctl daemon-reload

# Start and configure Indexer
if [[ -f /usr/share/wazuh-indexer/bin/indexer-security-init.sh ]]; then
  log_info "Setting up Wazuh Indexer..."
  
  systemctl enable wazuh-indexer
  systemctl start wazuh-indexer
  
  # Always run security init (it's idempotent)
  log_info "Running security initialization..."
  /usr/share/wazuh-indexer/bin/indexer-security-init.sh
  
  # Wait for indexer to be ready
  log_info "Waiting for Indexer to be ready..."
  for i in {1..30}; do
    if curl -k -s https://localhost:9200 >/dev/null 2>&1; then
      log_success "Indexer is ready"
      break
    fi
    sleep 2
  done
fi

# Configure and start Manager
if [[ -f /var/ossec/etc/ossec.conf && -d /etc/wazuh-indexer/certs ]]; then
  log_info "Configuring Wazuh Manager..."
  
  # Replace indexer configuration in one go
  sed -i '/<indexer>/,/<\/indexer>/c\
  <indexer>\
    <hosts>\
      <host>https://localhost:9200</host>\
    </hosts>\
    <ssl>\
      <certificate_authorities>\
        <ca>/etc/wazuh-indexer/certs/root-ca.pem</ca>\
      </certificate_authorities>\
      <certificate>/etc/wazuh-indexer/certs/indexer.pem</certificate>\
      <key>/etc/wazuh-indexer/certs/indexer-key.pem</key>\
    </ssl>\
  </indexer>' /var/ossec/etc/ossec.conf
  
  systemctl enable wazuh-manager
  systemctl start wazuh-manager
  
  # Wait for manager to be ready
  log_info "Waiting for Manager to be ready..."
  for i in {1..20}; do
    if systemctl is-active --quiet wazuh-manager; then
      log_success "Manager is ready"
      break
    fi
    sleep 2
  done
fi

# Configure and start Dashboard
if [[ -f /etc/wazuh-dashboard/opensearch_dashboards.yml && -d /etc/wazuh-indexer/certs ]]; then
  log_info "Configuring Wazuh Dashboard..."
  
  # Copy certificates to dashboard directory with proper permissions
  mkdir -p /etc/wazuh-dashboard/certs
  cp /etc/wazuh-indexer/certs/* /etc/wazuh-dashboard/certs/
  chmod 500 /etc/wazuh-dashboard/certs
  chmod 400 /etc/wazuh-dashboard/certs/*
  chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
  
  # Update certificate paths in config
  sed -i 's#server\.ssl\.key: "/etc/wazuh-dashboard/certs/dashboard-key\.pem"#server.ssl.key: "/etc/wazuh-dashboard/certs/indexer-key.pem"#' \
    /etc/wazuh-dashboard/opensearch_dashboards.yml
  
  sed -i 's#server\.ssl\.certificate: "/etc/wazuh-dashboard/certs/dashboard\.pem"#server.ssl.certificate: "/etc/wazuh-dashboard/certs/indexer.pem"#' \
    /etc/wazuh-dashboard/opensearch_dashboards.yml
  
  systemctl enable wazuh-dashboard
  systemctl start wazuh-dashboard
  
  # Wait for dashboard
  log_info "Waiting for Dashboard to be ready..."
  for i in {1..30}; do
    if curl -k -s https://localhost:443 >/dev/null 2>&1; then
      log_success "Dashboard is ready"
      break
    fi
    sleep 2
  done
fi

##############################################
# 9) Display summary
##############################################
echo
echo "===================================================="
echo -e "${GREEN}WAZUH DEV/TEST ENVIRONMENT READY${NC}"
echo "===================================================="

# Get IP addresses
MAIN_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || true)"
ALL_IPS="$(hostname -I 2>/dev/null || true)"

if [[ -n "${MAIN_IP:-}" ]]; then
  echo -e "${BLUE}Primary IP:${NC} $MAIN_IP"
fi

if [[ -n "${ALL_IPS:-}" ]]; then
  echo -e "${BLUE}All IPs:${NC} $ALL_IPS"
fi

echo
echo -e "${GREEN}Access URLs:${NC}"
echo "  Dashboard: https://${MAIN_IP:-localhost}"
echo "  Manager API: https://${MAIN_IP:-localhost}:55000"
echo "  Indexer: https://${MAIN_IP:-localhost}:9200"

echo
echo -e "${YELLOW}Default Credentials:${NC}"
echo "  Username: admin"
echo "  Password: admin"

echo
echo -e "${BLUE}Installed Components:${NC}"
rpm -q wazuh-indexer >/dev/null 2>&1 && echo "  ✓ Wazuh Indexer" || echo "  ✗ Wazuh Indexer"
rpm -q wazuh-manager >/dev/null 2>&1 && echo "  ✓ Wazuh Manager" || echo "  ✗ Wazuh Manager"  
rpm -q wazuh-dashboard >/dev/null 2>&1 && echo "  ✓ Wazuh Dashboard" || echo "  ✗ Wazuh Dashboard"

echo
echo -e "${YELLOW}Service Status:${NC}"
for service in wazuh-indexer wazuh-manager wazuh-dashboard; do
  if systemctl is-active --quiet "$service"; then
    echo -e "  $service: ${GREEN}active${NC}"
  else
    echo -e "  $service: ${RED}inactive${NC}"
  fi
done

echo
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  View logs: journalctl -u wazuh-{indexer,manager,dashboard}"
echo "  Check status: systemctl status wazuh-*"
echo "  Restart all: systemctl restart wazuh-*"

echo
echo "===================================================="
log_warn "Remember: This is a DEV/TEST setup with default credentials!"
echo "====================================================="
