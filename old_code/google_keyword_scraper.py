"""
Google Search Scraper for Scam Site Identification
===================================================
Searches Google for a given keyword and collects results (URL, title, snippet)
to help identify and report suspected scam sites to law enforcement.

Usage:
    python google_search_scraper.py
    python google_search_scraper.py --query "fake tech support" --max-results 20
    python google_search_scraper.py --query "phishing login page" --max-results 10 --output results.csv

Requirements:
    pip install requests beautifulsoup4
"""

import argparse
import csv
import json
import random
import sys
import time
from datetime import datetime
from urllib.parse import quote_plus, urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependencies. Install them with:")
    print("  pip install requests beautifulsoup4")
    sys.exit(1)


# ---------------------------------------------------------------------------
# User-Agent rotation to reduce blocking
# ---------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
]


def google_search(query: str, max_results: int = 10, lang: str = "en") -> list[dict]:
    """
    Scrape Google search results for *query* and return up to *max_results*
    entries, each a dict with keys: rank, title, url, domain, snippet.
    """
    results = []
    seen_urls = set()
    page = 0
    per_page = 10  # Google serves ~10 organic results per page

    while len(results) < max_results:
        start = page * per_page
        params = {
            "q": query,
            "start": str(start),
            "hl": lang,
            "num": str(per_page),
        }
        url = "https://www.google.com/search?" + "&".join(
            f"{k}={quote_plus(v)}" for k, v in params.items()
        )

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml",
            "Referer": "https://www.google.com/",
        }

        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"[!] Request failed (page {page}): {exc}")
            break

        soup = BeautifulSoup(resp.text, "html.parser")

        # Each organic result lives inside a div with class "g"
        result_divs = soup.select("div.g")
        if not result_divs:
            # Google may have changed layout or blocked us
            print("[!] No results found on page — Google may be blocking requests.")
            print("    Consider adding a delay, using a VPN, or switching to the")
            print("    Google Custom Search API (see --help).")
            break

        for div in result_divs:
            if len(results) >= max_results:
                break

            # --- URL & title ---
            link_tag = div.select_one("a[href]")
            if not link_tag:
                continue
            href = link_tag.get("href", "")
            if not href.startswith("http"):
                continue
            if href in seen_urls:
                continue

            title_tag = div.select_one("h3")
            title = title_tag.get_text(strip=True) if title_tag else "(no title)"

            # --- Snippet ---
            snippet = ""
            # Common snippet containers
            for selector in [
                "div[data-sncf]",
                "div.VwiC3b",
                "div[style='-webkit-line-clamp:2']",
                "span.aCOpRe",
            ]:
                snip_tag = div.select_one(selector)
                if snip_tag:
                    snippet = snip_tag.get_text(" ", strip=True)
                    break
            if not snippet:
                # Fallback: grab all text after the title
                all_text = div.get_text(" ", strip=True)
                if title in all_text:
                    snippet = all_text.split(title, 1)[-1].strip()

            domain = urlparse(href).netloc

            seen_urls.add(href)
            results.append(
                {
                    "rank": len(results) + 1,
                    "title": title,
                    "url": href,
                    "domain": domain,
                    "snippet": snippet[:300],
                }
            )

        page += 1
        # Polite delay between pages to avoid rate-limiting
        delay = random.uniform(2.0, 5.0)
        print(f"    … fetched page {page}, {len(results)} results so far "
              f"(waiting {delay:.1f}s)")
        time.sleep(delay)

    return results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_results(results: list[dict]) -> None:
    """Pretty-print results to the terminal."""
    if not results:
        print("\nNo results found.")
        return

    print(f"\n{'='*80}")
    print(f" {'RANK':<5} {'DOMAIN':<35} TITLE")
    print(f"{'='*80}")
    for r in results:
        print(f" {r['rank']:<5} {r['domain']:<35} {r['title'][:40]}")
        print(f"       {r['url']}")
        if r["snippet"]:
            print(f"       {r['snippet'][:100]}…" if len(r["snippet"]) > 100
                  else f"       {r['snippet']}")
        print()


def save_csv(results: list[dict], filepath: str) -> None:
    """Save results to a CSV file."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rank", "title", "url", "domain", "snippet"])
        writer.writeheader()
        writer.writerows(results)
    print(f"[+] Saved {len(results)} results to {filepath}")


def save_json(results: list[dict], filepath: str) -> None:
    """Save results to a JSON file."""
    payload = {
        "query": args.query,
        "timestamp": datetime.now().isoformat(),
        "total_results": len(results),
        "results": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved {len(results)} results to {filepath}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search Google by keyword to locate suspected scam sites.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python google_search_scraper.py
  python google_search_scraper.py -q "fake tech support scam" -n 30
  python google_search_scraper.py -q "phishing paypal" -n 20 -o scam_results.csv
  python google_search_scraper.py -q "crypto giveaway scam" -n 15 -o results.json

Tip: For heavy or repeated use, consider using the Google Custom Search
     JSON API (100 free queries/day) to avoid being blocked:
     https://developers.google.com/custom-search/v1/overview
""",
    )
    parser.add_argument("-q", "--query", type=str, default=None,
                        help="Search term / keyword (prompted if omitted)")
    parser.add_argument("-n", "--max-results", type=int, default=10,
                        help="Maximum number of results to collect (default: 10)")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="Save results to file (.csv or .json)")
    parser.add_argument("--lang", type=str, default="en",
                        help="Search language (default: en)")
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    # Interactive prompts if flags weren't supplied
    query = args.query
    if not query:
        query = input("Enter search keyword: ").strip()
        if not query:
            print("[!] No query entered. Exiting.")
            sys.exit(1)

    max_results = args.max_results
    if args.query is None:
        try:
            raw = input(f"Max results [{max_results}]: ").strip()
            if raw:
                max_results = int(raw)
        except ValueError:
            pass

    print(f"\n[*] Searching Google for: \"{query}\"  (max {max_results} results)\n")

    results = google_search(query, max_results=max_results, lang=args.lang)
    print_results(results)

    # Save if requested
    if args.output:
        if args.output.lower().endswith(".json"):
            save_json(results, args.output)
        else:
            save_csv(results, args.output)
    elif results:
        save = input("Save results? Enter filepath (.csv/.json) or press Enter to skip: ").strip()
        if save:
            if save.lower().endswith(".json"):
                save_json(results, save)
            else:
                if not save.lower().endswith(".csv"):
                    save += ".csv"
                save_csv(results, save)

    print("[*] Done.")