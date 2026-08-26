# Subhunter
Python-based subdomain reconnaissance tool that discovers subdomains, probes live HTTP targets, fingerprints technologies, analyzes security headers, and generates structured reports.

# SubHunter

**SubHunter** is a Python-based subdomain intelligence and reconnaissance tool designed to automate the early stages of authorized web reconnaissance.

It combines multiple subdomain discovery sources, performs concurrent HTTP probing, extracts basic target information, fingerprints common technologies, evaluates selected security headers, and generates JSON/TXT reports.

> **Version:** 1.0
> **Language:** Python 3
> **Purpose:** Security research, reconnaissance, and authorized asset discovery

---

## ⚠️ Legal & Ethical Disclaimer

SubHunter is intended **only for systems you own or have explicit permission to test**.

Do not use this tool against third-party infrastructure without authorization. Unauthorized reconnaissance or scanning may violate laws, contracts, or bug-bounty program rules.

The author is not responsible for misuse of this software.

---

## Features

### 🔎 Subdomain Discovery

SubHunter discovers subdomains using two sources:

* **crt.sh** Certificate Transparency data
* **Custom wordlist**

The results are combined and deduplicated automatically.

```text
crt.sh
   │
   ├── Certificate-based subdomains
   │
Wordlist
   │
   ├── Wordlist-generated subdomains
   │
   ▼
Combined unique targets
```

The discovery engine is implemented by the `SubdomainDiscovery` class.

---

### ⚡ Concurrent HTTP Probing

Discovered targets are converted into HTTPS URLs and probed concurrently using:

```python
ThreadPoolExecutor
```

The number of worker threads can be configured from the command line.

For each responsive target, SubHunter collects:

* URL
* HTTP status code
* Server header
* Page title
* Response headers
* Content-Length

The probing stage also records the total scan time.

---

### 🧬 Basic Technology Fingerprinting

SubHunter checks response headers for signatures associated with several technologies:

* Cloudflare
* Nginx
* Apache
* AWS
* Fastly
* Akamai

If no known signature is detected, the technology is reported as:

```text
Unknown
```

The fingerprinting logic is handled by the `Fingerprinter` class.

---

### 🛡️ Security Header Scoring

SubHunter checks for six HTTP security headers:

```text
X-Frame-Options
X-XSS-Protection
Content-Security-Policy
Strict-Transport-Security
X-Content-Type-Options
Referrer-Policy
```

The security score is calculated as the percentage of these headers present in the response.

For example:

```text
6 / 6 headers = 100%
3 / 6 headers = 50%
0 / 6 headers = 0%
```

> **Important:** This is a simple header-presence score, not a complete security assessment.

---

### 📊 Reporting

After reconnaissance, SubHunter generates:

* Console summary
* JSON report
* TXT report

Reports include:

* Target domain
* Timestamp
* Number of discovered targets
* Number of live targets
* Number of dead targets
* Weakest target based on header score
* Technology detection
* Security score
* Per-target findings

The reporting functionality is implemented by the `Reporter` class.

---

# Installation

## Requirements

* Python 3.11+
* Internet connection
* A wordlist file

Clone the repository:

```bash
git clone <YOUR_REPOSITORY_URL>
cd SubHunter
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

### Linux/macOS

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install requests beautifulsoup4
```

---

# Usage

Basic scan:

```bash
python3 subhunter.py -d example.com
```

Specify a custom wordlist:

```bash
python3 subhunter.py \
    -d example.com \
    -w wordlists.txt
```

Increase the number of threads:

```bash
python3 subhunter.py \
    -d example.com \
    -t 20
```

Enable verbose fingerprinting output:

```bash
python3 subhunter.py \
    -d example.com \
    -v
```

Specify an output directory:

```bash
python3 subhunter.py \
    -d example.com \
    -o results
```

Combine options:

```bash
python3 subhunter.py \
    -d example.com \
    -w wordlists.txt \
    -t 20 \
    -v \
    -o results
```

---

# Command-Line Options

| Option             | Description                              | Default         |
| ------------------ | ---------------------------------------- | --------------- |
| `-d`, `--domain`   | Target domain                            | Required        |
| `-w`, `--wordlist` | Wordlist path                            | `wordlists.txt` |
| `-t`, `--threads`  | Number of HTTP worker threads            | `10`            |
| `-v`, `--verbose`  | Display detailed fingerprint information | Disabled        |
| `-o`, `--output`   | Output directory                         | `results`       |
| `-p`, `--ports`    | Port list argument                       | Common ports    |

The argument parser currently exposes `--ports`, but the current implementation does not actually perform a port scan. This option should therefore be considered **reserved/planned functionality** rather than an implemented feature.

---

# Wordlist Format

SubHunter accepts a plain-text wordlist.

Example:

```text
www
api
dev
staging
admin
mail
portal
vpn
```

Comments beginning with `#` and empty lines are ignored.

Example:

```text
# Production
www
api

# Development
dev
staging
```

The words are combined with the target domain:

```text
www.example.com
api.example.com
dev.example.com
staging.example.com
```

---

# Workflow

SubHunter follows this pipeline:

```text
                    ┌───────────────┐
                    │    Domain     │
                    └───────┬───────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
        ┌───────────┐               ┌───────────┐
        │  crt.sh   │               │ Wordlist  │
        └─────┬─────┘               └─────┬─────┘
              │                           │
              └─────────────┬─────────────┘
                            ▼
                   ┌─────────────────┐
                   │ Deduplicate     │
                   │ Subdomains      │
                   └────────┬────────┘
                            ▼
                   ┌─────────────────┐
                   │ HTTP Prober     │
                   │ ThreadPool      │
                   └────────┬────────┘
                            ▼
                     ┌─────────────┐
                     │ Live Targets│
                     └──────┬──────┘
                            ▼
                   ┌─────────────────┐
                   │ Fingerprinter   │
                   ├─────────────────┤
                   │ Page Title      │
                   │ Technology      │
                   │ Security Score  │
                   └────────┬────────┘
                            ▼
                   ┌─────────────────┐
                   │    Reporter     │
                   ├─────────────────┤
                   │ Console         │
                   │ JSON             │
                   │ TXT              │
                   └─────────────────┘
```

---

# Example Output

A typical execution looks like:

```text
[*] Starting SubHunter against example.com

[+] Wordlist loaded: 100 subdomains
[+] crt.sh       : 25
[+] Wordlist     : 100
[+] Combined     : 118 unique

[*] Starting HTTP probing...

[+] Live : 12
[-] Dead : 106
[*] Time : 4.21s

[*] Fingerprinting live targets...

[+] https://api.example.com
    Title : API
    Tech  : nginx
    Score : 66%

============================================================
  SubHunter Summary — example.com
============================================================
[+] Discovered : 118
[+] Live       : 12
[-] Dead       : 106
============================================================

[+] https://api.example.com       | nginx        | Score: 66%
[+] https://www.example.com       | cloudflare   | Score: 83%

============================================================
[!] Weakest : https://api.example.com — 66%
```

---

# Output Files

By default, reports are saved inside:

```text
results/
```

Example:

```text
results/
├── subhunter_example.com_2026-08-26_04-30-12.json
└── subhunter_example.com_2026-08-26_04-30-12.txt
```

### JSON

The JSON report is suitable for further automation and processing.

Example structure:

```json
{
  "domain": "example.com",
  "timestamp": "2026-08-26_04-30-12",
  "total_discovered": 118,
  "total_live": 12,
  "total_dead": 106,
  "weakest_target": "https://api.example.com",
  "weakest_score": 66,
  "findings": []
}
```

### TXT

The TXT report provides a human-readable summary of the reconnaissance results.

---

# Project Structure

A recommended project layout:

```text
SubHunter/
│
├── subhunter.py
├── wordlists.txt
├── README.md
├── requirements.txt
│
└── results/
    ├── *.json
    └── *.txt
```

---

# Dependencies

Current external Python dependencies:

```text
requests
beautifulsoup4
```

Generate a requirements file:

```bash
pip freeze > requirements.txt
```

Or create one manually:

```text
requests
beautifulsoup4
```

Install them with:

```bash
pip install -r requirements.txt
```

---

# Architecture

SubHunter is currently organized around four primary classes.

### `SubdomainDiscovery`

Responsible for:

* crt.sh discovery
* wordlist loading
* combining and deduplicating targets

### `Prober`

Responsible for:

* concurrent HTTP requests
* live-target detection
* response metadata collection
* scan timing

### `Fingerprinter`

Responsible for:

* page title extraction
* technology detection
* security-header scoring

### `Reporter`

Responsible for:

* report generation
* JSON output
* TXT output
* console summary

The program's `main()` function coordinates these components in sequence.

---

# Security Considerations

SubHunter is a reconnaissance tool, so responsible usage matters.

## Use authorization

Only scan targets where you have explicit permission.

Good environments include:

* Your own infrastructure
* CTF environments
* Local labs
* Authorized penetration tests
* Bug-bounty targets explicitly permitted by their program

## Rate limiting

Increasing thread count does not automatically mean better reconnaissance.

Too many concurrent requests can:

* overload infrastructure
* trigger WAF/rate-limit controls
* generate unnecessary traffic
* potentially cause service degradation

Start conservatively.

## Security score limitations

The header score should **not** be interpreted as:

```text
80% = 80% secure
```

It only measures whether six selected headers are present.

A target can have all six headers and still contain serious vulnerabilities.

---

# Known Limitations

Current limitations include:

* HTTP probing is primarily HTTPS-oriented.
* Technology fingerprinting is based on simple header signatures.
* Security scoring checks header presence rather than configuration quality.
* Fingerprinting is currently performed sequentially after HTTP probing.
* Error handling in some areas is broad.
* The `--ports` argument exists but port scanning is not currently implemented.
* No DNS resolution stage is performed before HTTP probing.
* No wildcard DNS detection is implemented.
* No asynchronous HTTP implementation is currently used.
* No persistent database is used for results.

These are opportunities for future development rather than hidden functionality.

---

# Roadmap

Possible future improvements:

* [ ] Implement actual port scanning
* [ ] Add DNS resolution
* [ ] Detect wildcard DNS
* [ ] Add HTTP/HTTPS fallback
* [ ] Add concurrent fingerprinting
* [ ] Add configurable request timeout
* [ ] Add retry handling
* [ ] Add rate limiting
* [ ] Improve technology fingerprinting
* [ ] Improve security-header analysis
* [ ] Add CSV output
* [ ] Add structured logging
* [ ] Add unit tests with `pytest`
* [ ] Add configuration file support
* [ ] Split the monolithic script into Python modules
* [ ] Add CI testing
* [ ] Add Docker support

---

# Learning Objectives

This project was built to practice practical Python and cybersecurity concepts, including:

* Object-oriented programming
* Classes and methods
* Exception handling
* File handling
* HTTP requests with `requests`
* HTML parsing with BeautifulSoup
* Regular reconnaissance workflows
* Thread-based concurrency
* `ThreadPoolExecutor`
* CLI argument parsing with `argparse`
* JSON serialization
* Report generation
* Basic security-header analysis
* Basic technology fingerprinting

---

# Responsible Development

SubHunter is intentionally focused on **reconnaissance and information gathering** rather than exploitation.

It does not attempt to:

* exploit discovered vulnerabilities
* bypass authentication
* brute-force credentials
* execute payloads
* modify target systems

The goal is to build a reliable foundation for authorized security assessment.

---

# Author

**Rad Hasan**

Built as a Python cybersecurity learning project focused on understanding reconnaissance automation, HTTP requests, concurrency, and security analysis.

---

# License

Choose an appropriate license before publishing this project publicly.

For example:

```text
MIT License
```

If you use a license, include the complete license text in a separate `LICENSE` file.

---

## Final Note

SubHunter is a learning project. It is not intended to replace established reconnaissance frameworks or professional security assessment tools.

The real objective is understanding **how the automation works**, not simply running a tool.

> **Learn the Python. Understand the network. Automate the boring work. Verify everything.**



