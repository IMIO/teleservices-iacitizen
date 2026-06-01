#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

# installation path
install_path="/usr/lib/teleservices_iacitizen"

sudo -u hobo hobo-manage imio_indus_deploy --directory $install_path

# Deploy combo settings to all existing tenants
combo_settings="${install_path}/teleservices_iacitizen/combo/tenants/settings.py"
if [ -f "$combo_settings" ]; then
    for tenant_dir in /etc/combo/tenants/*/; do
        [ -d "$tenant_dir" ] && cp "$combo_settings" "${tenant_dir}settings.py"
    done
    service combo restart
fi
