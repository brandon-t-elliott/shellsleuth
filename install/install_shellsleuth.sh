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

# Check for python3 binary
if python3_path=$(find_binary "python3"); then
    echo "python3 is already installed at: $python3_path"
else
    echo "python3 is not installed. Please install it using your package manager. For example:"
    echo "  sudo apt-get install python3     # Debian/Ubuntu"
    echo "  sudo yum install python3         # RedHat/CentOS"
    exit 1
fi

# Check for ip binary
if ip_path=$(find_binary "ip"); then
    echo "ip is already installed at: $ip_path"
else
    echo "ip (part of iproute2) is not installed. Please install it using your package manager. For example:"
    echo "  sudo apt-get install iproute2     # Debian/Ubuntu"
    echo "  sudo yum install iproute          # RedHat/CentOS"
    exit 1
fi

# Check for ss binary
if ss_path=$(find_binary "ss"); then
    echo "ss is already installed at: $ss_path"
else
    echo "ss (part of iproute2) is not installed. Please install it using your package manager. For example:"
    echo "  sudo apt-get install iproute2     # Debian/Ubuntu"
    echo "  sudo yum install iproute          # RedHat/CentOS"
    exit 1
fi

# Check for mkdir binary
if mkdir_path=$(find_binary "mkdir"); then
    :
else
    echo "Unsupported operating system. Unable to find `mkdir` binary"
    exit 1
fi

# Check for cat binary
if cat_path=$(find_binary "cat"); then
    :
else
    echo "Unsupported operating system. Unable to find `cat` binary"
    exit 1
fi

# Check for cp binary
if cp_path=$(find_binary "cp"); then
    :
else
    echo "Unsupported operating system. Unable to find `cp` binary"
    exit 1
fi

# Check for systemctl binary
if systemctl_path=$(find_binary "systemctl"); then
    :
else
    echo "Unsupported operating system. Unable to find `systemctl` binary"
    exit 1
fi

# Check for sleep binary
if sleep_path=$(find_binary "sleep"); then
    :
else
    echo "Unsupported operating system. Unable to find `sleep` binary"
    exit 1
fi

echo "All required binaries are already installed. Dependencies check passed."

# Variables
SERVICE_NAME="shellsleuth"
SERVICE_DESCRIPTION="ShellSleuth - Detect and kill reverse shells"
INSTALL_DIR="/opt/shellsleuth"
SCRIPT_NAME="shellsleuth.py"
SYSTEMD_DIR="/etc/systemd/system"

if [[ ! -f "../$SCRIPT_NAME" ]]; then
    echo "Error: $SCRIPT_NAME does not exist in the parent directory."
    exit 1
fi

# Create installation directory
$mkdir_path -p $INSTALL_DIR

# Copy files to installation directory
$cp_path ../$SCRIPT_NAME $INSTALL_DIR

# Parse arguments
STRICT=""
LOG_ONLY=""
WHITELIST=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --strict)
      STRICT="--strict"
      shift
      ;;
    --log-only)
      LOG_ONLY="--log-only"
      shift
      ;;
    --whitelist)
      if [[ -z $2 ]]; then
        echo "Error: --whitelist argument requires a comma-separated list of binaries to whitelist."
        echo "Installation aborted..."
        exit 1
      fi
      WHITELIST="--whitelist '$2'"
      shift 2
      ;;
    *)
      echo "Error: Unknown argument: $1"
      echo "Installation aborted..."
      exit 1
      ;;
  esac
done

# Create systemd service file
$cat_path <<EOL > $SYSTEMD_DIR/$SERVICE_NAME.service
[Unit]
Description=$SERVICE_DESCRIPTION
After=network.target

[Service]
ExecStart=$python3_path $INSTALL_DIR/$SCRIPT_NAME $STRICT $LOG_ONLY $WHITELIST
WorkingDirectory=$INSTALL_DIR
StandardOutput=journal
StandardError=journal
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd and enable service
$systemctl_path daemon-reload
$systemctl_path enable $SERVICE_NAME.service

# Start the service
$systemctl_path start $SERVICE_NAME.service

# Restart the service in case we re-installed
$systemctl_path restart $SERVICE_NAME.service

# Sleep for 2 seconds before checking the service status
$sleep_path 2

# Check if the service is running
SERVICE_STATUS=$($systemctl_path is-active $SERVICE_NAME.service)
if [ "$SERVICE_STATUS" = "active" ]; then
    echo "ShellSleuth service successfully installed and started."
else
    echo "ShellSleuth service failed to start. Please check your arguments."
    $systemctl_path status $SERVICE_NAME.service
    exit 1
fi