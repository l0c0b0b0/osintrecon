# OSINTRecon

OSINTRecon is a multi-threaded reconnaissance tool which performs automated enumeration of subdomains, ports, emails and vulnerabilities. It is intended as a time-saving tool on penetration testing.

The tool works by firstly performing a enumeration of subdomains and dns records. From those initial results, the tool will launch further enumeration scans of those subdomains using a number of different tools.

Everything in the tool is highly configurable. The author will not be held responsible for negative actions that result from the mis-use of this tool.

**Disclaimer: While OSITNRecon endeavors to perform as much identification and enumeration of the domain as possible, there is no guarantee that every output will be identified, or that every information will be fully catched.**

## Origin

l0c0t0!!!

## Installation

OSINTRecon is a manually installation. Before installation using any of these methods, certain requirements need to be fulfilled. If you have not refreshed your apt cache recently, run the following command so you are installing the latest available packages:


```bash
sudo apt update
```

### Python3 

OSITNRecon requires the usage of Python3.8+ and pip, which can be installed on Kali Linux using the following commands:

```bash
sudo apt install python3
sudo apt install python3-pip
sudo apt install python3-venv
```

### Supporting Packages

Several commands used in OSINTRecon may need to be installed, deppending on your OS: 

* SpiderFoot 4.0.0
* DiG 9.19.21-1
* DNSRecon version 1.1.5
* Sublist3r
* Amass v4.2.0
* Fierce
* cloud-enum
* Asn 0.76.1
* Metagoofil v1.2.0

On Kali Linux, you can ensure these are all installed using the following commands:

```bash
sudo apt install spiderfoot dig dnsrecon sublist3r amass fierce cloud-enum asn metagoofil
```

### Installation Method: Manually

Install and execute `osintrecon.py` from within the OSINT directory, install the dependencies:

Create a virtual enviroment with python3:
```bash
(root) python3 -m venv osintrecon
(root) source osintrecon/bin/activate
(root) pip install -r requirements.txt
```
To exit the virtual enviromment:

```bash
(root) (osintrecon) deactivate
```

You will then be able to run the `osintrecon.py` script:

```bash
(root) python3 osintrecon.py [OPTIONS] target.com
```

## Usage

OSINTRecon uses Python 3 specific functionality and does not support Python 2.

```
usage: osintrecon.py [-h] [-t TARGET_FILE] [-ct <number>] [-cs <number>]
                [--profile PROFILE_NAME] [-o OUTPUT_DIR] [--single-target]
                [--only-scans-dir] [-v] [--disable-sanity-checks]
                [targets ...]

OSINT Enumeration

positional arguments:
  targets               Resolvable hostnames (e.g. foo.bar) to scan or IP addresses (e.g.
                        10.0.0.1), CIDR notation (e.g. 10.0.0.1/24)

options:
  -h, --help            show this help message and exit
  -t TARGET_FILE, --targets TARGET_FILE
                        Read only IP address from file, every domain will be translate to
                        ip.
  -ct <number>, --concurrent-targets <number>
                        The maximum number of target hosts to scan concurrently. Default:
                        2
  -cs <number>, --concurrent-scans <number>
                        The maximum number of scans to perform per target host. Default:
                        3
  --profile PROFILE_NAME
                        The OSINT basic scanning profile to use (defined in osint-basic-
                        profiles.toml). Default: default
  -o OUTPUT_DIR, --output OUTPUT_DIR
                        The output directory for results. Default: osint
  --single-target       Only scan a domain.
  --only-scans-dir      Only create the "scans" directory for results. Other directories
                        (e.g. report) will not be created. Default: false
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  --disable-sanity-checks
                        Disable sanity checks that would otherwise prevent the scans from
                        running. Default: false

```

### Verbosity

AutoRecon supports four levels of verbosity:

* (none) Minimal output. OSINTRecon will announce when scanning targets starts / ends.
* (-v) Verbose output. OSINTRecon will additionally announce when plugins start running, and report found.
* (-vv) Very verbose output. OSINTRecon will additionally specify the exact commands which are being run by plugins, highlight any patterns which are matched in command output, and announce when plugins end.
* (-vvv) Very, very verbose output. OSINTRecon will output everything. Literally every line from all commands which are currently running. When scanning multiple targets concurrently, this can lead to a ridiculous amount of output. It is not advised to use -vvv unless you absolutely need to see live output from commands.

### Results

By default, results will be stored in the ./osint directory. A new sub directory is created for every target. The structure of this sub directory is:

```
.
osint
└── target
    ├── report
    │   ├── csv
    │   │   └── IpSubdomain.csv
    │   │   └── Patterns.csv
    │   └── ip_sub.txt
    └── scans
        ├── _commands.log
        ├── _errors.log
        ├── _manual_commands.txt
        ├── _patterns.log
        ├── files\
        ├── info\
        ├── ports\
        ├── recon\
        ├── vulns\
        └── web\

```
The scans directory is where all results from scans performed by AutoRecon will go. This includes port scans / service detection scans. It also contains two other files:
* \_commands.log contains a list of every command OSINTRecon ran against the target. This is useful if one of the commands fails and you want to run it again with modifications.
* \_manual_commands.txt contains any commands that are deemed "too dangerous" to run automatically, either because they are too intrusive, require modification based on human analysis, or just work better when there is a human monitoring them.

If a scan results in an error, a file called \_errors.log will also appear in the scans directory with some details to alert the user.

If output matches a defined pattern, a file called \_patterns.log will also appear in the scans directory with details about the matched output.
