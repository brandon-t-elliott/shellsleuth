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

install_dependency() {
    local package_name=$1
    if apt_get_path=$(find_binary "apt-get"); then
        $sudo_path $apt_get_path update && $sudo_path $apt_get_path install -y "$package_name"
    elif yum_path=$(find_binary "yum"); then
        if [ "$package_name" == "iproute2" ]; then
            package_name="iproute"
        fi
        $sudo_path $yum_path install -y "$package_name"
    else
        echo "Unsupported operating system. Please install $package_name manually."
        exit 1
    fi
}

# Check for sudo binary
if sudo_path=$(find_binary "sudo"); then
    :
else
    echo "Unsupported operating system. Please install dependencies manually."
    exit 1
fi

# Check for python3 binary
if python3_path=$(find_binary "python3"); then
    echo "python3 is already installed at: $python3_path"
else
    echo "python3 is not installed. Installing..."
    install_dependency "python3"
fi

# Check for ip binary
if ip_path=$(find_binary "ip"); then
    echo "ip is already installed at: $ip_path"
else
    echo "ip is not installed. Installing..."
    install_dependency "iproute2"
fi

# Check for ss binary
if ss_path=$(find_binary "ss"); then
    echo "ss is already installed at: $ss_path"
else
    echo "ss is not installed. Installing..."
    install_dependency "iproute2"
fi

echo "All required dependencies are installed."