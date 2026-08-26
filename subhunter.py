# subhunter.py structure
import os, json, requests, time, threading
import argparse as agp
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

TOOL_NAME = "SubHunter"
VERSION = "1.0"

def banner():
    print(f"""
  ███████╗██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
      ██╔╝██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
     ██╔╝ ██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
     ██║  ╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
     ╚═╝   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    {TOOL_NAME} v{VERSION} — Subdomain Intelligence Tool
    """)


class SubdomainDiscovery:
    def __init__(self, domain, wordlist_path):
        self.domain = domain
        self.wordlist_path = wordlist_path

    def from_crtsh(self):
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            response = requests.get(url, timeout=30)
            if response.status_code != 200:
                print(f"[!] crt.sh returned {response.status_code}")
                return []
            if not response.text.strip():
                print("[!] crt.sh returned empty reposne")
                return []
            data = response.json()
            subdomains = set()
            for entry in data:
                name = entry["name_value"]
                if "*" not in name:
                    subdomains.add(name)
            return list(subdomains)
        except Exception as e:
            print(f"[!] crt.sh error: {e}")
            return []

    def from_wordlists(self):
        try:
            with open(self.wordlist_path, "r") as f:
                words = [
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                ]
            subdomains = [f"{word}.{self.domain}" for word in words]
            print(f"[+] Wordlist loaded: {len(subdomains)} subdomains")
            return subdomains
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {self.wordlist_path}")
            return []

    def combine(self):
        cert_subs = self.from_crtsh()
        word_subs = self.from_wordlists()
        combined = list(set(cert_subs + word_subs))
        print(f"[+] crt.sh       : {len(cert_subs)}")
        print(f"[+] Wordlist     : {len(word_subs)}")
        print(f"[+] Combined     : {len(combined)} unique")
        return combined

class Prober:
    def __init__(self, targets, threads=20):
        self.targets = targets
        self.threads = threads
        self.results = []
        self.lock = threading.Lock()
        self.scan_time = 0

    def probe(self, url):
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
        }
        try:
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            title = "No title"
            try:
                soup = BeautifulSoup(response.text, "html.parser")
                t = soup.find("title")
                if t:
                    title = t.text.strip()
            except:
                pass

            return {
                "url": url,
                "status": response.status_code,
                "server": response.headers.get("Server", "Unknown"),
                "title": title,
                "headers": response.headers,
                "content_length": response.headers.get("Content-Length", "Unknown")
            }
        except (requests.exceptions.ConnectionError, 
        requests.exceptions.Timeout,
        requests.exceptions.RequestException):
            return None

    def run(self):
        start_time = time.time()
        urls = [t if t.startswith("http") else f"https://{t}" for t in self.targets]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            raw = list(executor.map(self.probe, urls))
        with self.lock:
            self.results = [r for r in raw if r is not None]
        self.scan_time = time.time() - start_time

    def get_live(self):
        return self.results

class Fingerprinter:
    SECURITY_HEADERS = [
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    TECH_SIGNATURES = {
        "cloudflare": ["cloudflare", "cf-ray"],
        "nginx": ["nginx"],
        "apache": ["apache"],
        "aws": ["awselb", "amazonaws"],
        "fastly": ["fastly"],
        "akamai": ["akamaighost"]
    }

    def __init__(self, result):
        self.result = result
        self.findings = {}

    def fetch(self):
        try:
            self.response = requests.get(self.result["url"], timeout=10)
        except Exception as e:
            print(f"[!] Error fetching {self.result['url']}: {e}")

    def get_title(self):
        if not self.response:
            return "Unknown"
        try:
            soup = BeautifulSoup(self.response.text, "html.parser")
            title = soup.find("title")
            return title.text.strip() if title else "No title"
        except:
            return "Unknown"

    def get_security_score(self):
        headers = self.result["headers"]
        present = [h for h in self.SECURITY_HEADERS if h in headers]
        return int((len(present) / len(self.SECURITY_HEADERS)) * 100)

    def detect_tech(self):
        headers_str = str(self.result["headers"]).lower()
        for tech, signatures in self.TECH_SIGNATURES.items():
            for sign in signatures:
                if sign in headers_str:
                    return tech
        return "Unknown"

    def analyze(self):
        self.findings = {
            "url": self.result["url"],
            "status": self.result["status"],
            "title": self.result["title"],
            "score": self.get_security_score(),
            "tech": self.detect_tech()
        }
        return self.findings

class Reporter:
    def __init__(self, domain, targets, live, fingerprints):
        self.domain = domain
        self.targets = targets
        self.live = live
        self.fingerprints = fingerprints
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def build_report(self):
        weakest = min(self.fingerprints, key=lambda x: x["score"]) if self.fingerprints else None
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "total_discovered": len(self.targets),
            "total_live": len(self.live),
            "total_dead": len(self.targets) - len(self.live),
            "weakest_target": weakest["url"] if weakest else None,
            "weakest_score": weakest["score"] if weakest else None,
            "findings": [
                {**f, "headers": dict(f.get("headers", {}))} 
                for f in self.fingerprints
            ]
        }

    def save_json(self, output_dir="results"):
        os.makedirs(output_dir, exist_ok=True)
        report = self.build_report()
        filepath = os.path.join(output_dir, f"subhunter_{self.domain}_{self.timestamp}.json")
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON saved : {filepath}")
        return filepath

    def save_txt(self, output_dir="results"):
        os.makedirs(output_dir, exist_ok=True)
        report = self.build_report()
        filepath = os.path.join(output_dir, f"subhunter_{self.domain}_{self.timestamp}.txt")
        with open(filepath, "w") as f:
            f.write(f"SubHunter Report — {self.domain}\n")
            f.write(f"Timestamp : {self.timestamp}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Total Discovered : {report['total_discovered']}\n")
            f.write(f"Total Live       : {report['total_live']}\n")
            f.write(f"Total Dead       : {report['total_dead']}\n\n")
            f.write("=" * 50 + "\n")
            f.write("FINDINGS\n")
            f.write("=" * 50 + "\n\n")
            for finding in self.fingerprints:
                f.write(f"[+] {finding['url']}\n")
                f.write(f"    Title : {finding['title']}\n")
                f.write(f"    Tech  : {finding['tech']}\n")
                f.write(f"    Score : {finding['score']}%\n\n")
            if report["weakest_target"]:
                f.write(f"\n[!] Weakest : {report['weakest_target']} — {report['weakest_score']}%\n")
        print(f"[+] TXT saved  : {filepath}")
        return filepath

    def print_summary(self):
        report = self.build_report()
        print(f"\n{'=' * 70}")
        print(f"  SubHunter Summary — {self.domain}")
        print(f"{'=' * 70}")
        print(f"[+] Discovered : {report['total_discovered']}")
        print(f"[+] Live       : {report['total_live']}")
        print(f"[-] Dead       : {report['total_dead']}")
        print(f"{'=' * 70}")
        for finding in self.fingerprints:
            print(f"[+] {finding['url']:<40} | {finding['tech']:<12} | Score: {finding['score']}%")
        print(f"{'=' * 70}")
        if report["weakest_target"]:
            print(f"[!] Weakest : {report['weakest_target']} — {report['weakest_score']}%")


def parse_args():
    parser = agp.ArgumentParser(
        description="SubHunter Recon Tool",
        epilog="Example: python3 subhunter.py -d example.com -t 20 -v"
    )
    parser.add_argument("-d", "--domain", required=True, help="Domain Name")
    parser.add_argument("-w", "--wordlist", default="wordlists.txt", help="Wordlist File")
    parser.add_argument("-t", "--threads", default=10, type=int, help="Number of Threads")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-o", "--output", default="results", help="Output Directory")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[21,22,23,25,53,80,443,8000,8080,8443],
        help="Port to scan (default: common ports)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.output.endswith(".txt") or args.output.endswith(".json"):
        print("[!] -o should be a directory, not a filename. Using 'results/'")
        args.output = "results"

    banner()
    print(f"\n[*] Starting SubHunter against {args.domain}")

    discovery = SubdomainDiscovery(
        args.domain,
        args.wordlist
    )

    targets = discovery.combine()

    if not targets:
        print("[!] No subdomains discovered.")
        return

    print("\n[*] Starting HTTP probing...")

    prober = Prober(
        targets,
        threads=args.threads
    )

    prober.run()
    live = prober.get_live()

    print(f"\n[+] Live : {len(live)}")
    print(f"[-] Dead : {len(targets) - len(live)}")
    print(f"[*] Time : {prober.scan_time:.2f}s")

    if not live:
        print("[!] No live targets found.")
        return

    print("\n[*] Fingerprinting live targets...")

    fingerprints = []

    for result in live:
        fp = Fingerprinter(result)
        findings = fp.analyze()
        fingerprints.append(findings)

        if args.verbose:
            print(f"\n[+] {findings['url']}")
            print(f"    Title : {findings['title']}")
            print(f"    Tech  : {findings['tech']}")
            print(f"    Score : {findings['score']}%")

    reporter = Reporter(
        args.domain,
        targets,
        live,
        fingerprints
    )

    reporter.print_summary()
    reporter.save_json(args.output)
    reporter.save_txt(args.output)

    print("\n[+] SubHunter completed successfully.")

if __name__ == "__main__":
    main()