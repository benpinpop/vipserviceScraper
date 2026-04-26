import json
import os
import time
import requests

from dotenv import load_dotenv
load_dotenv()

full_data = {}

API_URL = "https://scambuster.intelligenceforgood.org/api/submit"
API_KEY = os.getenv("SCAMBUSTERS_API_KEY")

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

sites = [
    {"site_url": "https://scam1.com",
     "wallets": [{"address": "0xAAA...", "chain": "eth"}]},
    {"site_url": "https://scam2.com"},
]


def main():
    with open('logs/full_extraction_data_with_validations.json', mode='r', encoding='utf-8') as file:
        full_data = json.load(file)
       
    for i, site_data in enumerate(sites):
        resp = requests.post(API_URL, json=site_data, headers=HEADERS)

        if resp.status_code == 201:
            r = resp.json()
            print(f"[{i+1}/{len(sites)}] Queued: {r['site_url']}")
        elif resp.status_code == 429:
            print("Rate limited — waiting 30s...")
            time.sleep(30)
            resp = requests.post(API_URL, json=site_data, headers=HEADERS)
        elif resp.status_code == 403:
            err = resp.json().get("error", "")
            if "approval" in err.lower() or "cannot submit" in err.lower():
                print("Not approved for /submit yet! Share your scraper code with Sam.")
                print("GitHub: smabryCFRL — see the Authentication docs.")
            else:
                print("Key expired! Run /rotate-api-key in Discord.")
            break
        else:
            print(f"Error {resp.status_code}: {resp.json()}")

        time.sleep(1.5)
