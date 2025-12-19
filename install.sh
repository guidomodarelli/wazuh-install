#!/bin/bash

##############################################
# 1) Detect architecture & package type
##############################################
ARCH=$(uname -m)
PKG_TYPE=""
BASE_URL="https://packages-dev.wazuh.com/nightly-backup"

if command -v rpm >/dev/null 2>&1; then
    PKG_TYPE="rpm"
    case "$ARCH" in
        amd64)    ARCH="x86_64" ;;
        arm64)    ARCH="aarch64" ;;
    esac
elif command -v dpkg >/dev/null 2>&1; then
    PKG_TYPE="deb"
    case "$ARCH" in
        x86_64)   ARCH="amd64" ;;
        aarch64)  ARCH="arm64" ;;
        armv7l)   ARCH="armhf" ;;
    esac
else
    echo "[ERROR] Neither rpm nor dpkg found – cannot install."
    exit 1
fi

echo "[INFO] Detected architecture: $ARCH"
echo "[INFO] Package type: $PKG_TYPE"

##############################################
# 2) Extract latest timestamp from HTTP headers
##############################################
HTTP_DATE=$(curl -sI "$BASE_URL" | grep -i '^Date:' | cut -d' ' -f2-6)
LATEST_DATE=$(date -d "$HTTP_DATE" +"%Y-%m-%d" 2>/dev/null)

if [ -z "$LATEST_DATE" ]; then
    echo "[ERROR] Cannot extract date from host."
    exit 1
fi

REPO_URL="$BASE_URL/$LATEST_DATE"
echo "[INFO] Latest Wazuh nightly date: $LATEST_DATE"
echo "[INFO] Using repository: $REPO_URL"

##############################################
# 3) Define package filenames
##############################################
if [[ "$PKG_TYPE" == "rpm" ]]; then
    INDEXER_PKG="wazuh-indexer-5.0.0-latest.${ARCH}.rpm"
    MANAGER_PKG="wazuh-manager-5.0.0-latest.${ARCH}.rpm"
    DASHBOARD_PKG="wazuh-dashboard-5.0.0-latest.${ARCH}.rpm"
else
    INDEXER_PKG="wazuh-indexer_5.0.0-latest_${ARCH}.deb"
    MANAGER_PKG="wazuh-manager_5.0.0-latest_${ARCH}.deb"
    DASHBOARD_PKG="wazuh-dashboard_5.0.0-latest_${ARCH}.deb"
fi

echo "[INFO] Packages to download:"
echo "  $INDEXER_PKG"
echo "  $MANAGER_PKG"
echo "  $DASHBOARD_PKG"

##############################################
# 4) Download latest packages
##############################################
for PKG in "$INDEXER_PKG" "$MANAGER_PKG" "$DASHBOARD_PKG"; do
    echo "[INFO] Downloading $PKG ..."
    curl -sS --fail -L "$REPO_URL/$PKG" -o "$PKG"
done

##############################################
# 5) Interactive install/uninstall function
##############################################
install_pkg() {
    local pkg=$1
    local name=$2

    echo "[INFO] Checking $name installation..."

    if [[ "$PKG_TYPE" == "rpm" ]]; then
        if rpm -q "$name" >/dev/null 2>&1; then
            echo "[INFO] $name detected as already installed."
            read -p "Uninstall and reinstall $name? (y/N): " choice
        fi

        if [[ -z "$choice" || "$choice" =~ ^[Yy]$ ]]; then
            if [[ "$name" == "wazuh-indexer" ]]; then
              GENERATE_CERTS=true rpm -ivh --replacepkgs "$pkg"
            else 
              rpm -ivh --replacepkgs "$pkg"
            fi
        fi
    else
        if dpkg -l | grep -q "^ii\s\+$name"; then
            echo "[INFO] $name detected as already installed."
            read -p "Uninstall and reinstall $name? (y/N): " choice
        fi

        if [[ -z "$choice" || "$choice" =~ ^[Yy]$ ]]; then
          if [[ "$name" == "wazuh-indexer" ]]; then
            GENERATE_CERTS=true dpkg -i "$pkg"
          else 
            dpkg -i "$pkg"
          fi
        fi
    fi
}

##############################################
# 6) Install the packages
##############################################
install_pkg "$INDEXER_PKG"  "wazuh-indexer"
install_pkg "$MANAGER_PKG"  "wazuh-manager"
install_pkg "$DASHBOARD_PKG" "wazuh-dashboard"

##############################################
# 7) All in one configuration
##############################################

systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

/usr/share/wazuh-indexer/bin/indexer-security-init.sh

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

mkdir /etc/wazuh-dashboard/certs
cp /etc/wazuh-indexer/certs/* /etc/wazuh-dashboard/certs
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

sed -i 's#server\.ssl\.key: "/etc/wazuh-dashboard/certs/dashboard-key\.pem"#server.ssl.key: "/etc/wazuh-dashboard/certs/indexer-key.pem"#' /etc/wazuh-dashboard/opensearch_dashboards.yml
sed -i 's#server\.ssl\.certificate: "/etc/wazuh-dashboard/certs/dashboard\.pem"#server.ssl.certificate: "/etc/wazuh-dashboard/certs/indexer.pem"#' /etc/wazuh-dashboard/opensearch_dashboards.yml

systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

ip=$(hostname -I | awk '{print $1}')

echo
echo "======================================================"
echo " WAZUH INSTALL COMPLETE — latest packages used"
echo " Dashboard (default): https://${ip}"
echo "======================================================"
echo