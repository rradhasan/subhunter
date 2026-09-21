import sys, requests

try:
    domain = sys.argv[1]
    if not domain or "." not in domain:
        print("[!] Invalid domain. Example: hackerone.com")
        sys.exit(1)
except IndexError:
    print("[!] Domain name can't be empty")
    sys.exit(1)

try:
    response = requests.post(
        "http://127.0.0.1:5000/api/scan",
        json={"domain": domain},
        timeout=30
    )

    if response.status_code not in (200, 201):
        print(f"[!] Scan failed with status code: {response.status_code}")
        print(response.text)
        sys.exit(1)

    results = response.json()
    print(f"\n[*] Scanning domain: {results['domain']}")
    print(f"[+] Scan ID        : {results['scan_id']}")
    print(f"[+] Discovered     : {results['total_discovered']}")
    print(f"[+] Live           : {results['total_live']}")
    print(f"[+] Dead           : {results['total_dead']}")
    print(f"\n[*] Findings:")
    for fp in results['findings']:
        print(f"    [+] {fp['url']} | {fp['status']} | {fp['tech']} | {fp['score']}%")

except requests.exceptions.RequestException as error:
    print(f"[!] Request failed: {error}")
    sys.exit(1)

except ValueError:
    print("[!] Server returned invalid JSON")
    sys.exit(1)
