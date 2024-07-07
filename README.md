# ShellSleuth

ShellSleuth is designed to detect and kill reverse shell connections on a linux system. It continuously looks through established network connections and identifies reverse shells and terminates all processes spawned by them. 

It can optionally be ran in --log-only mode to only detect and log them (it is recommended to run it with --log-only for an initial period of time such as a month or more to help identify any potential false positives on a particular system).

Strict mode offers a higher level of security as it does not check the process against a list of common reverse shell binaries, but will be more prone to false positives. False positives can be whitelisted by specifying a comma-separated list of binaries to --whitelist.

## Dependencies
- `python3` (doesn't require any additional pip packages apart from what's installed by default)
- `ss` and `ip` binaries (iproute/iproute2 - should already be present unless using a minimal install of linux)

## Check Dependencies

```bash
bash shellsleuth/install/check_dependencies.sh
```

## Install Dependencies (Manually)

### Debian/Ubuntu

```bash
sudo apt-get install python3 iproute2
```

### Fedora/RedHat

```bash
sudo yum install python3 iproute
```

## Try it out in --log-only mode, without installing
```bash
sudo python3 shellsleuth.py --log-only
```

## Install ShellSleuth as a systemd service

1. **Clone the repository:**
    ```bash
    git clone https://github.com/brandon-t-elliott/shellsleuth.git
    ```

2. **Install dependencies (automatically):**
    ```bash
    cd shellsleuth/install
    sudo bash install_dependencies.sh
    ```

3. **Install ShellSleuth with --log-only (recommended at first)**
    ```bash
    sudo bash install_shellsleuth.sh --log-only
    ```
    or

   **Install ShellSleuth (after running in --log-only and checking for false positives)**
    ```bash
    sudo bash install_shellsleuth.sh
    ```

    or

   **Install ShellSleuth in --strict mode (please use with caution, more prone to false positives)**
    ```bash
    sudo bash install_shellsleuth.sh --strict
    ```

    or

   **Install ShellSleuth with --strict and a --whitelist (for any false positives)**
    ```bash
    sudo bash install_shellsleuth.sh --strict --whitelist "nginx,sshd"
    ```

## Manually Modify the Systemd Service

1. Use your text editor of choice to modify `/etc/systemd/system/shellsleuth.service` with the options you want.

2. `sudo systemctl daemon-reload`

3. `sudo systemctl restart shellsleuth`

## Uninstall ShellSleuth
```bash
sudo bash shellsleuth/uninstall/uninstall_shellsleuth.sh
```

## Usage

```bash
usage: shellsleuth.py [-h] [--version] [--strict] [--log-only] [--whitelist WHITELIST]
```

## Arguments

| Argument                 | Description                                                                                              |
|------------------------|----------------------------------------------------------------------------------------------------------|
| `-h, --help`           | show this help message and exit                                                                          |
| `--version`            | show program's version number and exit                                                                   |
| `--strict`             | Enable strict mode - doesn't check if process is a common reverse shell binary - may be more prone to false positives, but less prone to false negatives |
| `--log-only`           | Only log reverse shell detections, do not kill any processes                                             |
| `--whitelist WHITELIST`| Comma-separated list of binaries to whitelist - suppresses detections for these binaries                  |

## Review Logs (Manually)

```bash
sudo less /var/log/shellsleuth.log
```

## Run Unit Tests

```bash
sudo python3 -m unittest tests/unit_tests.py
```

## Other Testing

Aside from the unit tests created, very limited testing has been done so far (I'm currently testing it in my homelab on about 20 servers). Please use with caution and test with `--log-only` first. I don't recommend running this in production environments.

## Contributors

Brandon T. Elliott - [Connect on LinkedIn](https://www.linkedin.com/in/brandon-t-elliott/)

## License

ShellSleuth is licensed under the Apache 2.0 License. See the [LICENSE](https://github.com/brandon-t-elliott/shellsleuth/blob/main/LICENSE) file for details.

## Disclaimer

ShellSleuth is provided "as is", without any warranties, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors be liable for any claim, damages, or other liability arising from the use of the software.