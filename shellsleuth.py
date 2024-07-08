#!/usr/bin/env python3
import subprocess
import time
import re
import os
import signal
import traceback
import argparse
from datetime import datetime, timedelta
import sched
import sys
import hashlib

__version__ = "1.0.0"

# Scheduler for running the main loop
scheduler = sched.scheduler(time.time, time.sleep)

# Common reverse shell binaries patterns (only used when not in --strict mode)
revshell_patterns = [
    'sh', 'bash', 'pwsh', 'ash', 'bsh', 'csh', 'ksh', 'zsh', 'pdksh',
    'tcsh', 'mksh', 'dash', 'fish', 'osh', 'elvish', 'es', 'xonsh',
    'oksh', 'lksh', 'nc', 'ncat', 'netcat', 'openssl', 'perl', 'python', 'python2.7',
    'python2', 'python3', 'ruby', 'busybox', 'curl', 'php', 'rcat',
    'socat', 'telnet', 'lua', 'lua5.1', 'go', 'v', 'awk', 'crystal'
]

# Stores the last logged time of reverse shells (only used when in --log-only mode)
last_logged = {}

# Stores the last established connections hash for making checks more efficient
last_established_connections_hash = ""

def get_local_ip_addresses(ip_path):
    """Get the local IP addresses of the machine."""
    ip_addresses = {"0.0.0.0", "[::]"}

    try:
        result = subprocess.run([ip_path, 'addr'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        ipv4_pattern = re.compile(r'inet (\d+\.\d+\.\d+\.\d+)/\d+')
        ipv6_pattern = re.compile(r'inet6 ([a-fA-F0-9:]+)/\d+')

        for line in output.split('\n'):
            ipv4_match = ipv4_pattern.search(line)
            if ipv4_match:
                ip_addresses.add(ipv4_match.group(1))

            ipv6_match = ipv6_pattern.search(line)
            if ipv6_match:
                ip_addresses.add(ipv6_match.group(1))

    except FileNotFoundError:
        log(f"Missing `ip` dependency. Exiting.")
        sys.exit(1)
    except Exception as e:
        log(f"Error getting IP addresses from network interfaces: {e}")
    
    return list(ip_addresses)

def get_ppid(pid):
    """Get the parent process ID (PPID) of a given PID."""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except FileNotFoundError:
        return None
    except Exception as e:
        log(f"Error getting PPID for PID {pid}: {e}")

    return None

def search_parent_pids(pid, list_of_pids_to_search):
    """Search a list of pids and determine if any are a parent pid of a supplied pid."""
    list_of_pids_to_search.sort()
    lowest_pid = list_of_pids_to_search[0] if list_of_pids_to_search else None

    while pid not in list_of_pids_to_search:
        pid = get_ppid(pid)
        
        if pid is None or (lowest_pid is not None and pid < lowest_pid):
            return False
    
    return True

def get_parent_pids(pid, list_of_pids_to_search):
    """Search a list of pids and return a list of parent pids for the supplied pid (excluding the list of pids)."""
    list_of_pids_to_search.sort()
    lowest_pid = list_of_pids_to_search[0] if list_of_pids_to_search else None

    parent_pids = set()

    while pid not in list_of_pids_to_search:
        pid = get_ppid(pid)
        
        if pid is None or (lowest_pid is not None and pid < lowest_pid):
            return parent_pids
        
        if pid not in list_of_pids_to_search:
            parent_pids.add(pid)
    
    return parent_pids

def log(activity):
    """Log activity to the console and a log file."""
    message = f"{datetime.now().isoformat()} - {activity}"
    print(message)
    try:
        with open("/var/log/shellsleuth.log", "a") as log_file:
            log_file.write(f"{message}\n")
    except Exception as e:
        print(f"Failed to log activity: {e}")

def kill_process(pid):
    """Kill a process by its PID."""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        log(f"Process with PID {pid} does not exist.")
    except PermissionError:
        log(f"Permission denied to terminate PID {pid}.")
    except Exception as e:
        log(f"An exception occurred when trying to terminate PID {pid}: {traceback.format_exc()}")

def get_listening_ports(ss_path):
    """Use `ss` to get all listening ports on the local system. Do not include loopback addresses."""
    try:
        result = subprocess.run([ss_path, '-ltanup'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        log(f"Missing `ss` dependency. Exiting.")
        sys.exit(1)
    except Exception as e:
        log(f"Error getting listening ports: {e}")
    
    if result.returncode != 0:
        print(f"Error running ss: {result.stderr}")
        return []
    
    connections = result.stdout
    
    listening_ports= []
    for line in connections.split('\n'):
        if 'LISTEN' in line:
            parts = line.split()
            if len(parts) >= 6:
                local_address = parts[3]

                address = local_address.rsplit(':', 1)[0]
                if not address.startswith('127.') and not address == '[::1]':
                    port = int(local_address.rsplit(':', 1)[1])
                    listening_ports.append(port)
    
    return listening_ports

def get_established_connections(ss_path):
    """Use `ss` to get all ESTAB (established) connections."""
    global last_established_connections_hash

    try:
        result = subprocess.run([ss_path, '-tanup'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        log(f"Missing `ss` dependency. Exiting.")
        sys.exit(1)
    except Exception as e:
        log(f"Error getting established connections: {e}")

    if result.returncode != 0:
        print(f"Error running ss: {result.stderr}")
        return []

    connections = result.stdout
    established_connections = [line for line in connections.split('\n') if 'ESTAB' in line]

    if not established_connections:
        return False

    established_connections_hash = hashlib.sha256('\n'.join(established_connections).encode('utf-8')).hexdigest()

    if last_established_connections_hash == established_connections_hash:
        return False
    else:
        last_established_connections_hash = established_connections_hash

    return established_connections

def parse_connection_info(connection):
    """Parse a line of `ss` output and return the parsed connection info."""
    parts = re.split(r'\s+', connection)
    if len(parts) < 6:
        return False

    local_address_port = parts[3]
    remote_address_port = parts[4]
    process_info = parts[5] if len(parts) > 5 else ""

    binary_matches = re.findall(r'\("(\w+)",pid=', process_info)
    binaries = [binary for binary in binary_matches]

    pid_matches = re.findall(r'pid=(\d+)', process_info)
    pids = [int(pid) for pid in pid_matches]

    fd_matches = re.findall(r'fd=(\d+)', process_info)
    fds = [int(fd) for fd in fd_matches]

    local_ip, local_port = local_address_port.rsplit(':', 1)
    remote_ip, remote_port = remote_address_port.rsplit(':', 1)

    local_port = int(local_port)
    remote_port = int(remote_port)

    return [local_ip, local_port, remote_ip, remote_port, pids, fds, binaries]

def identify_suspicious_connections(listening_ports, established_connections, local_ips, strict, whitelist):
    """Identify suspicious connections based on established connections."""
    suspicious_connections = []
    suspicious_ips = set()
    suspicious_pid_info = {}

    for connection in established_connections:
        parsed_connection = parse_connection_info(connection)
        local_ip, local_port, remote_ip, remote_port, pids, fds, binaries = parsed_connection
        suspicious_connection = [local_ip, local_port, remote_ip, remote_port, pids, fds]

        matched_binary = next((binary for binary in binaries if binary in revshell_patterns), None)
        is_whitelisted = next((binary for binary in binaries if binary in whitelist), None)

        if (strict or matched_binary) and not is_whitelisted:
            if remote_ip not in local_ips and local_port not in listening_ports:
                suspicious_ips.add(remote_ip)

                suspicious_connections.append(suspicious_connection)
                for pid in pids:
                    suspicious_pid_info[pid] = connection

    for connection in established_connections:
        parsed_connection = parse_connection_info(connection)
        local_ip, local_port, remote_ip, remote_port, pids, fds, binaries = parsed_connection
        suspicious_connection = [local_ip, local_port, remote_ip, remote_port, pids, fds]

        is_whitelisted = next((binary for binary in binaries if binary in whitelist), None)

        if remote_ip in suspicious_ips and suspicious_connection not in suspicious_connections and not is_whitelisted:
            suspicious_connections.append(suspicious_connection)
            for pid in pids:
                suspicious_pid_info[pid] = connection

    return suspicious_connections, suspicious_ips, suspicious_pid_info

def check_last_logged(suspicious_ip, suspicious_pids, log_only):
    """Check if we already logged the reverse shell in the last hour. Returns True if we should skip logging."""
    no_log = False

    if not log_only: # we don't need to throttle logs if we aren't in --log-only
        return no_log
    
    pid_string = " ".join(str(pid) for pid in suspicious_pids)
    fingerprint = f"{suspicious_ip}-{pid_string}"
    current_time = datetime.now()
    if fingerprint in last_logged:
        last_logged_time = last_logged[fingerprint]
        if current_time - last_logged_time < timedelta(hours=1):
            no_log = True  # Skip logging

    if not no_log:
        last_logged[fingerprint] = current_time

    return no_log

def handle_reverse_shell(suspicious_ip, local_pids, suspicious_pids, suspicious_pid_info, strict, log_only):
    """Log and/or terminate reverse shells that were detected."""
    KERNEL_PIDS = 300  # Kernel PIDs threshold
    
    no_log = check_last_logged(suspicious_ip, suspicious_pids, log_only)

    if not no_log:
        log(f"Reverse shell detected from IP: {suspicious_ip}")
        
    malicious_pids = set()

    for pid in suspicious_pids:
        malicious_pids.add(pid)
        parent_pids = get_parent_pids(pid, local_pids)
        malicious_pids.update(parent_pids)

    for pid in malicious_pids:
        if pid >= 0:
            restricted_pid = True

            if strict or pid > KERNEL_PIDS:
                restricted_pid = False

            if not log_only:
                if not restricted_pid:
                    kill_process(pid)
                    if not no_log:
                        log(f"Terminated PID: {pid}")
                else:
                    if not no_log:
                        log(f"Didn't terminate PID because it's likely a kernel PID: {pid}")
            else:
                if not no_log:
                    log(f"Didn't terminate PID because shellsleuth is in --log-only mode: {pid}")

        if not no_log:
            if pid in suspicious_pid_info:
                log(f"Connection info: {suspicious_pid_info[pid]}")

def check_for_reverse_shells(local_ips, strict, log_only, ss_path, whitelist, established_connections):
    """Check for reverse shells by inspecting established network connections."""
    try:
        listening_ports = get_listening_ports(ss_path)

        suspicious_connections, suspicious_ips, suspicious_pid_info = identify_suspicious_connections(listening_ports, established_connections, local_ips, strict, whitelist)

        for suspicious_ip in suspicious_ips:
            inbound, outbound, is_reverse_shell, is_suspicious_fds = False, False, False, False
            local_pids = []
            suspicious_pids = []

            for connection in suspicious_connections:
                local_ip, local_port, remote_ip, remote_port, pids, fds = connection
                if remote_ip == suspicious_ip:
                    local_inbound = False

                    for listening_port in listening_ports:
                        if local_port == listening_port:
                            inbound, local_inbound = True, True
                            local_pids.extend(pids)
                    
                    if not local_inbound:
                        outbound = True
                        suspicious_pids.extend(pids)

                        if 0 in fds and 1 in fds and len(fds) >= 3:
                            is_suspicious_fds = True

            if inbound and outbound and local_pids is not None and suspicious_pids is not None:
                for pid in suspicious_pids:
                    is_spawned_pid = search_parent_pids(pid, local_pids)

                    if is_spawned_pid or is_suspicious_fds:
                        is_reverse_shell = True

            if is_reverse_shell:
                handle_reverse_shell(suspicious_ip, local_pids, suspicious_pids, suspicious_pid_info, strict, log_only)

    except Exception as e:
        log(f"An exception occurred: {traceback.format_exc()}")

def get_binary_path(binary_name):
    """Get the full path to a binary."""
    try:
        common_bin_dirs = ['/usr/bin', '/usr/sbin', '/bin', '/sbin']

        for directory in common_bin_dirs:
            binary_path = os.path.join(directory, binary_name)
            if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
                return binary_path
        
        raise FileNotFoundError(f"`{binary_name}` not found on system.")
    except Exception as e:
        print(e)
        print(f"Please install missing `{binary_name}` dependency. Exiting...")
        sys.exit(1)

def main(scheduler, strict, log_only, ip_path, ss_path, whitelist):
    """The main loop."""
    established_connections = get_established_connections(ss_path)

    # if no established connections or established connections hasn't changed, skip checking to improve efficiency
    if established_connections:
        local_ips = get_local_ip_addresses(ip_path)
        check_for_reverse_shells(local_ips, strict, log_only, ss_path, whitelist, established_connections)

    scheduler.enter(0.2, 1, main, (scheduler, strict, log_only, ip_path, ss_path, whitelist))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShellSleuth - Detect and kill reverse shells")
    parser.add_argument('--version', action='version', version=f'ShellSleuth {__version__}')
    parser.add_argument('--strict', action='store_true', help="Enable strict mode - doesn't check if process is a common reverse shell binary - may be more prone to false positives, but less prone to false negatives")
    parser.add_argument('--log-only', action='store_true', help="Only log reverse shell detections, do not kill any processes")
    parser.add_argument('--whitelist', type=str, help="Comma-separated list of binaries to whitelist - suppresses detections for these binaries")
    args = parser.parse_args()

    ip_path = get_binary_path('ip')
    ss_path = get_binary_path('ss')

    whitelist = [item.strip() for item in args.whitelist.split(',')] if args.whitelist else []

    scheduler.enter(0.2, 1, main, (scheduler, args.strict, args.log_only, ip_path, ss_path, whitelist))
    scheduler.run()