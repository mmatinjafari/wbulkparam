import requests
import argparse
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, parse_qs

def make_session():
    """Create a requests session with automatic retries."""
    s = requests.Session()
    retries = Retry(total=5, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

def fetch_and_extract(domain):
    """Stream all URLs from the Wayback Machine and extract parameters on the fly."""
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    session = make_session()

    print(f"[*] Fetching URLs for {domain} from Wayback Machine (streaming)...")

    try:
        resp = session.get(url, timeout=300, stream=True)
        resp.raise_for_status()
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    params = set()
    url_count = 0

    try:
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            url_count += 1
            if url_count % 5000 == 0:
                sys.stdout.write(f"\r[*] Processed: {url_count} URLs | Params: {len(params)}")
                sys.stdout.flush()
            try:
                qs = urlparse(line).query
                if qs:
                    params.update(parse_qs(qs).keys())
            except Exception:
                continue
    except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError) as e:
        print(f"\n[!] Connection lost after {url_count} URLs — keeping {len(params)} params collected so far")
    except KeyboardInterrupt:
        print(f"\n[!] Stopped — keeping {len(params)} params collected so far")

    print(f"\r[+] Total: {url_count} URLs | {len(params)} unique parameters")
    return sorted(params)

def main():
    parser = argparse.ArgumentParser(description="Fetch Wayback Machine URLs and extract parameters.")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Save results to file")
    args = parser.parse_args()

    params = fetch_and_extract(args.domain)

    if not params:
        print("[-] No parameters found.")
        return

    print()
    for p in params:
        print(p)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(params) + "\n")
        print(f"\n[+] Saved to {args.output}")

if __name__ == "__main__":
    main()
