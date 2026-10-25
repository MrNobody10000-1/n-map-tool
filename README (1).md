# PortPeek

> A lightweight Python port scanner that finds open TCP ports, names the services, and reads banners. No dependencies.

PortPeek is a small nmap-style TCP port scanner. It finds open ports on a host, names the service on each one, and can read a short banner from the service. The whole tool is one file, `portscan.py`, and it uses only the Python standard library, so there is nothing to install besides Python itself.

> **Legal notice.** Only scan systems you own or have written permission to test. Scanning other people's systems can be illegal. You are responsible for how you use this tool.

## Features

- TCP connect scan with many parallel connections
- Scan a hostname, an IP address, or a whole block such as `192.168.1.0/24` (up to 1,024 hosts)
- Port lists, ranges, all 65,535 ports, or the most common ports with `--top`
- Service names for open ports
- Optional banner grabbing (SSH, FTP, SMTP and HTTP greetings)
- Save results as JSON or CSV
- Works on Linux, macOS and Windows

## Requirements

- Python 3.8 or newer
- No third-party packages (`requirements.txt` is included for completeness and installs nothing)

## Installation

### 1. Install Python 3

Check whether you already have it:

```bash
python3 --version
```

On Windows, use `py --version` instead. If Python is missing or older than 3.8, install it:

**Ubuntu / Debian**

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

**Fedora**

```bash
sudo dnf install -y python3 python3-pip
```

**macOS** (with [Homebrew](https://brew.sh))

```bash
brew install python
```

**Windows** (PowerShell)

```powershell
winget install Python.Python.3.12
```

Or download the installer from https://www.python.org/downloads/ and tick "Add python.exe to PATH".

### 2. Get the project files

Put `portscan.py`, `requirements.txt`, `README.md` and `LICENSE` in one folder, then open a terminal in that folder.

If you keep the project in a Git repository, clone it instead:

```bash
git clone <your-repository-url>
cd <your-repository-folder>
```

### 3. (Optional) Create a virtual environment

This keeps the project separate from your system Python. It is optional because the scanner has no dependencies.

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks the activate script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once and try again.

### 4. Install the requirements

```bash
pip install -r requirements.txt
```

This finishes without installing anything, because the scanner needs no extra packages.

### 5. Check that it works

**Linux / macOS**

```bash
python3 portscan.py --help
```

**Windows**

```powershell
py portscan.py --help
```

On Linux and macOS you can also make the script executable and run it directly:

```bash
chmod +x portscan.py
./portscan.py 127.0.0.1
```

## Usage

```text
python3 portscan.py TARGET [options]
```

`TARGET` is a hostname, an IP address, or a CIDR block.

| Option | Meaning |
| --- | --- |
| `-p`, `--ports` | Ports to scan: `22,80`, `1-1024`, or `-` for all ports. Default: `1-1024` |
| `--top N` | Scan the N most common ports (1 to 101). Cannot be combined with `-p` |
| `-t`, `--timeout` | Seconds to wait per port. Default: `1.0` |
| `-w`, `--workers` | Parallel connections. Default: `100`, maximum `1000` |
| `-b`, `--banner` | Read a short banner from open ports |
| `--show-closed` | Also list closed and filtered ports |
| `--json FILE` | Save results to a JSON file |
| `--csv FILE` | Save results to a CSV file |

### Examples

Scan your own computer, ports 1 to 1024:

```bash
python3 portscan.py 127.0.0.1
```

Scan specific ports and read banners:

```bash
python3 portscan.py 192.168.1.10 -p 22,80,443 --banner
```

Scan the 100 most common ports on a small network:

```bash
python3 portscan.py 192.168.1.0/30 --top 100
```

Scan every port, with more parallel connections, and save the results:

```bash
python3 portscan.py 192.168.1.10 -p - --workers 300 --json results.json --csv results.csv
```

Scan the test host that the nmap project provides for this purpose:

```bash
python3 portscan.py scanme.nmap.org -p 22,80,443
```

On Windows, replace `python3` with `py`.

### Example output

This is the result of scanning two local test servers with `-p 40000-40100 --banner`:

```text
Scan report for 127.0.0.1
  PORT        STATE     SERVICE           BANNER
  40022/tcp   open      unknown           SSH-2.0-TestServer_1.0
  40080/tcp   open      unknown           HTTP/1.0 200 OK Server: testhttpd
  2 open of 101 scanned in 0.5s
```

### Port states

- **open**: a service accepted the connection.
- **closed**: the host answered and refused the connection. Shown only with `--show-closed`.
- **filtered**: no answer within the timeout, often because a firewall drops the traffic. Shown only with `--show-closed`.

### Saved results

`--json` writes one entry per host with its IP address and a list of ports. `--csv` writes one row per port with the columns `host, ip, port, state, service, banner`.

## Tips

- Raise `--timeout` (for example `-t 3`) on slow or distant networks, or you may miss open ports.
- Lower `--workers` if the scan makes your router or the target struggle.
- Press `Ctrl+C` to stop. When you are scanning several hosts, the hosts that already finished are still saved to the JSON and CSV files. The host being scanned at that moment is not.
- Scanning a whole network with `-p -` takes a long time. Start with `--top 100`.

## Limitations

- It performs a full TCP connect scan only. It does not do SYN (stealth) scanning, UDP scanning, or OS detection.
- IPv4 only.
- A banner appears only when the service sends a greeting or answers a plain HTTP request.
- Service names come from your system's services list and are a guess based on the port number, not a check of what is really running.

## License

Released under the MIT License. See the [LICENSE](LICENSE) file.
