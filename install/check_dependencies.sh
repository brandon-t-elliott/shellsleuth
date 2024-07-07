#!/bin/bash

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

echo "All required binaries are installed."