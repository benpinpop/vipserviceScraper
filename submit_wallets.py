import json
import os
import time
from urllib import response
import requests

from dotenv import load_dotenv
load_dotenv()

full_data = {}

API_URL = "https://scambuster.intelligenceforgood.org/api/submit"
API_KEY = os.getenv("SCAM_BUSTERS_API_KEY")

print(API_KEY)

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

""" example site schema for /submit endpoint:
sites = [
    {"site_url": "https://scam1.com",
     "wallets": [{"address": "0xAAA...", "chain": "eth"}]},
    {"site_url": "https://scam2.com"},
]
"""

"""
Valid Chain Codes
Code     Blockchain               Address Prefix
───────────────────────────────────────────────────
btc      Bitcoin                  1..., 3..., bc1...
eth      Ethereum (ERC-20)        0x...
trx      Tron (TRC-20)            T...
xrp      XRP (Ripple)             r...
bsc      BNB Smart Chain (BEP-20) 0x...
ltc      Litecoin                 L..., M..., ltc1...
doge     Dogecoin                 D...
bch      Bitcoin Cash             q..., bitcoincash:...
ada      Cardano                  addr1...
dash     Dash                     X...
matic    Polygon                  0x...
arb      Arbitrum                 0x...
avax     Avalanche                0x...
op       Optimism                 0x...
"""

def can_curl_website(site_url):
    try:
        response = requests.get("https://" + site_url, timeout=10)
        return response.status_code == 200
    except requests.RequestException:
        return False

def formatWalletsTable(wallets):
    formatted_wallets = []

    for wallet in wallets:
        if not wallet["is_valid"] or not wallet["address"] or not wallet["is_supported"]:
            continue

        if formatted_wallets and any(w["address"] == wallet["address"] for w in formatted_wallets):
            continue

        chain = wallet["network"].lower()
        address = wallet["address"]

        formatted_wallets.append({
            "chain": chain,
            "address": address
        })

    return formatted_wallets

def submitAllSitesForApi(api,table):
    # print(table)
    correlatedSites = table.get("correlated-sites", [])
    wallets = table.get("wallets", [])
    wallets = formatWalletsTable(wallets)

    for site_url in correlatedSites:
        # if not can_curl_website(site_url):
            # print(f"Cannot reach {site_url}.")
            # continue

        print('Submitting site:', site_url)

        payload = {
            "site_url": site_url,
            "wallets": wallets
        }

        print(payload)

        response = requests.post(API_URL, headers=HEADERS, json=payload)
        print('Response:', response.status_code, response.text)
        time.sleep(5)  # Sleep to avoid hitting rate limits
        

def main():
    with open("logs/submit_data.json", mode='r', encoding='utf-8') as file:
        full_data = json.load(file)
        
    for category, table in full_data.items():
        if category != "web-apis":
            continue

        
        for api, api_data in table.items():
            print(api)
            submitAllSitesForApi(api, api_data)

main()