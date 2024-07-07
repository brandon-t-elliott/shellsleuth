#!/bin/bash

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

find_binary() {
    local binary_name=$1
    local common_bin_dirs=("/usr/bin" "/usr/sbin" "/bin" "/sbin")

    for directory in "${common_bin_dirs[@]}"; do
        local binary_path="$directory/$binary_name"
        if [[ -x "$binary_path" ]]; then
            echo "$binary_path"
            return 0
        fi
    done

    echo "$binary_name not found in common binary directories" >&2
    return 1
}

# Check for sudo binary
if sudo_path=$(find_binary "sudo"); then
    :
else
    echo "Unsupported operating system. Unable to find `sudo` binary"
    exit 1
fi

# Check for rm binary
if rm_path=$(find_binary "rm"); then
    :
else
    echo "Unsupported operating system. Unable to find `rm` binary"
    exit 1
fi

# Check for systemctl binary
if systemctl_path=$(find_binary "systemctl"); then
    :
else
    echo "Unsupported operating system. Unable to find `systemctl` binary"
    exit 1
fi

# Variables
SERVICE_NAME="shellsleuth"
INSTALL_DIR="/opt/shellsleuth"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Stop the service
echo "Stopping the ${SERVICE_NAME} service..."
$sudo_path $systemctl_path stop ${SERVICE_NAME}

# Disable the service
echo "Disabling the ${SERVICE_NAME} service..."
$sudo_path $systemctl_path disable ${SERVICE_NAME}

# Remove the service file
if [ -f "${SERVICE_FILE}" ]; then
    echo "Removing the service file..."
    $sudo_path $rm_path ${SERVICE_FILE}
else
    echo "Service file not found. Skipping..."
fi

# Reload systemd daemon
echo "Reloading systemd daemon..."
$sudo_path $systemctl_path daemon-reload

# Remove the installation directory
if [ -d "${INSTALL_DIR}" ]; then
    echo "Removing the installation directory..."
    $sudo_path $rm_path -r ${INSTALL_DIR}
else
    echo "Installation directory not found. Skipping..."
fi

# Confirm uninstallation
echo "${SERVICE_NAME} has been successfully uninstalled."
