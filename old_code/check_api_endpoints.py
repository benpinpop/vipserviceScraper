import csv
import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Any
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
CSV_FILE = "logs/urlscan.csv"
OUTPUT_FILE = "logs/api_check_results.json"
TIMEOUT = 10  # seconds
REQUEST_DELAY = 0.1  # seconds between requests to avoid overwhelming servers
MAX_WORKERS = 10  # number of concurrent threads

def check_api_endpoint(domain: str) -> Dict[str, Any]:
    """
    Check if an API endpoint is alive and retrieve wallet data for Bitcoin and Ethereum.
    
    Args:
        domain: The domain to check (e.g., 'mininginvestmentfx.live')
    
    Returns:
        Dictionary with site status and API response data for both coin types
    """
    result = {
        "domain": domain,
        "url": "",
        "status": "unknown",
        "http_status_code": None,
        "error": None,
        "response_time": None,
        "checked_at": datetime.now().isoformat(),
        "coins": {
            "Bitcoin": {
                "api_response": None,
                "wallet_data": None
            },
            "Ethereum": {
                "api_response": None,
                "wallet_data": None
            }
        }
    }
    
    coin_types = ["Bitcoin", "Ethereum"]
    
    try:
        # Construct the API URL
        url = f"https://user.{domain}/ops/users"
        result["url"] = url
        
        headers = {
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Query both coin types
        for coin_type in coin_types:
            payload = f"request=getcoin&type={coin_type}"
            
            # Make the request
            start_time = time.time()
            response = requests.post(url, headers=headers, data=payload, timeout=TIMEOUT, verify=False)
            response_time = time.time() - start_time
            result["response_time"] = response_time
            result["http_status_code"] = response.status_code
            
            # Store raw response
            result["coins"][coin_type]["api_response"] = response.text
            
            # Try to parse JSON response
            try:
                json_response = response.json()
                result["coins"][coin_type]["wallet_data"] = json_response
            except json.JSONDecodeError:
                # Response is not JSON, but site is still alive
                result["coins"][coin_type]["wallet_data"] = None
        
        # Determine if site is alive (status code 200-299 or 400-499 indicates site responded)
        if 200 <= response.status_code < 500:
            result["status"] = "alive"
        else:
            result["status"] = "not_responding"
            
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
        result["error"] = "Request timed out"
    except requests.exceptions.ConnectionError:
        result["status"] = "not_alive"
        result["error"] = "Connection error - domain may not exist or server not responding"
    except requests.exceptions.SSLError:
        result["status"] = "ssl_error"
        result["error"] = "SSL/HTTPS certificate error"
    except requests.exceptions.RequestException as e:
        result["status"] = "error"
        result["error"] = str(e)
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Unexpected error: {str(e)}"
    
    return result

def main():
    """Main function to process all domains from CSV and output JSON results."""
    
    print(f"Starting API endpoint check...")
    print(f"CSV file: {CSV_FILE}")
    print(f"Output file: {OUTPUT_FILE}")
    print("-" * 80)
    
    # Read domains from CSV
    domains = []
    try:
        with open(CSV_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get('Page Apex Domain', '').strip()
                if domain:
                    domains.append(domain)
    except FileNotFoundError:
        print(f"ERROR: CSV file not found: {CSV_FILE}")
        sys.exit(1)
    
    print(f"Found {len(domains)} domains to check")
    print("-" * 80)
    
    # Check each domain using thread pool
    results = {
        "metadata": {
            "total_domains": len(domains),
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "status_summary": {}
        },
        "results": []
    }
    
    print(f"Starting checks with {MAX_WORKERS} concurrent threads...")
    print("-" * 80)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        future_to_domain = {executor.submit(check_api_endpoint, domain): domain for domain in domains}
        
        # Process completed tasks as they finish
        completed = 0
        for future in as_completed(future_to_domain):
            completed += 1
            domain = future_to_domain[future]
            try:
                result = future.result()
                results["results"].append(result)
                print(f"[{completed}/{len(domains)}] {domain}: {result['status']}")
            except Exception as e:
                print(f"[{completed}/{len(domains)}] {domain}: ERROR - {str(e)}")
    
    # Generate summary statistics
    status_counts = {}
    for result in results["results"]:
        status = result["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    
    results["metadata"]["status_summary"] = status_counts
    results["metadata"]["completed_at"] = datetime.now().isoformat()
    
    # Save results to JSON
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print("-" * 80)
        print(f"Results saved to: {OUTPUT_FILE}")
    except Exception as e:
        print(f"ERROR: Could not save results to {OUTPUT_FILE}: {e}")
        sys.exit(1)
    
    # Print summary
    print("-" * 80)
    print("SUMMARY:")
    print(f"Total domains checked: {results['metadata']['total_domains']}")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")
    
    # Print sample results
    alive_results = [r for r in results["results"] if r["status"] == "alive"]
    if alive_results:
        print(f"\nSample alive sites with responses:")
        for result in alive_results[:3]:
            print(f"  {result['domain']}:")
            for coin in ["Bitcoin", "Ethereum"]:
                api_resp = result["coins"][coin]["api_response"]
                if api_resp:
                    print(f"    {coin}: {api_resp[:80]}...")

if __name__ == "__main__":
    # Disable SSL warnings (not recommended for production)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()
