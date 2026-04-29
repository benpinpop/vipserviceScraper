import csv
import json
import time
import uuid
import os
import requests
import coinaddrvalidator
from threading import Thread

from dotenv import load_dotenv
load_dotenv()

SCAMBUSTERS_REPORTED_ENDPOINT = "https://scambuster.intelligenceforgood.org/api/check"
URLSCAN_API_ENDPOINT = "https://urlscan.io/api/v1/result/"
URLSCAN_SCAN_ENDPOINT = "https://urlscan.io/api/v1/scan/"

SCAM_BUSTERS_API_KEY = os.getenv('SCAM_BUSTERS_API_KEY')
URL_SCAN_API_KEY = os.getenv('URL_SCAN_API_KEY')

api_to_wallet_table = {}

print('SCAM_BUSTERS_API_KEY:', SCAM_BUSTERS_API_KEY, URL_SCAN_API_KEY)

def is_site_reported(site_url: str):
  headers = {"Authorization": f"Bearer {SCAM_BUSTERS_API_KEY}"}
  params = {"site_url": site_url}

  response = requests.get(SCAMBUSTERS_REPORTED_ENDPOINT, headers=headers, params=params, timeout=30)
  response.raise_for_status()

  response = response.json()
  print(response)
  if response.get("has_wallets"):
     return True
  else:
     return False
    
def extract_unique_domains(domainFileName: str, outputFileName: str):
   domainList = []

   with open("logs/urlscan.csv", mode='r', newline='', encoding='utf-8') as file:
    reader = csv.reader(file)
    for row in reader:
        print(row)
        if row[21] not in domainList:
            domainList.append(row[21])
            continue
        print('Duplicate site:', row[21])

    domainList.pop(0)
    print(len(domainList),domainList)

    with open(outputFileName, mode='w', encoding='utf-8') as file:
        for site in domainList:
            file.write(site + '\n')

def check_sites_reported_bulk():
    isReported = []
    isUnreported = []

    with open('logs/filteredDomains.txt', mode='r', newline='', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if is_site_reported(line):
                print('Reported:', line)
                isReported.append(line)
            else:
                print('Unreported:', line)
                isUnreported.append(line)
            time.sleep(2)

    with open('logs/unreported.txt', mode='w', encoding='utf-8') as file:
        for site in isUnreported:
            file.write(site + '\n')

    with open('logs/reported.txt', mode='w', encoding='utf-8') as file:
        for site in isReported:
            file.write(site + '\n')

def get_urlscan_result(uuid: str):
    url = URLSCAN_API_ENDPOINT + uuid
    response = requests.get(url, timeout=30, headers={"api-key": URL_SCAN_API_KEY})
    response.raise_for_status()
    return response.json()

def scan_website_with_urlscan(site_url: str):
    payload = {
        "url": site_url,
        "public": "on"
    }
    response = requests.post(URLSCAN_SCAN_ENDPOINT, json=payload, headers={"api-key": URL_SCAN_API_KEY}, timeout=30)
    response.raise_for_status()
    return response.json()

def get_unreported_sites():
    with open('logs/unreported.txt', mode='r', newline='', encoding='utf-8') as file:
        return [line.strip() for line in file]
    
def get_uuid_from_unreported_site(site_url: str):
    with open('logs/urlscan.csv', mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[21] == site_url:
                url = row[8]
                url = url.replace("https://urlscan.io/result/", "")
                return url

def get_webapi_from_site():
    site_to_api_domains = {}
    unreportedSites = get_unreported_sites()
    print('Total unreported sites:', len(unreportedSites))

    for site in unreportedSites:
        print('Progress:' + str(unreportedSites.index(site) + 1) + '/' + str(len(unreportedSites)) + ' - Checking site:', site)
        uuid = get_uuid_from_unreported_site(site)
        domains = get_urlscan_result(uuid).get('lists', {}).get('domains', [])
    
        for domainName in domains:
            if "webapi." in domainName.lower():
                site_to_api_domains[site] = domainName
                print('Unreported site with API domain:', site, 'API domain:', domainName)
                
        if site not in site_to_api_domains:
            for domainName in domains:
                if "api." in domainName.lower():
                    site_to_api_domains[site] = domainName
                    print('Unreported site with API domain:', site, 'API domain:', domainName)
                    break

            site_to_api_domains[site] = "UNKNOWN"
            print('NO API DOMAIN FOUND:', site, domains)
        

    with open('logs/site_to_api.txt', mode='w', encoding='utf-8') as file:
        for site, api_domain in site_to_api_domains.items():
            file.write(f"{site}|{api_domain}|{get_uuid_from_unreported_site(site)}\n")            

def create_json_of_web_apis_to_sites():
    with open("logs/site_to_api.txt", mode='r', newline='', encoding='utf-8') as file:
        api_to_site = {}
        for line in file:
            site, api_domain, uuid = line.strip().split('|')

            if api_domain not in api_to_site:
                api_to_site[api_domain] = {}

            if site not in api_to_site[api_domain]:
                api_to_site[api_domain][site] = uuid

    with open('logs/api_to_site.json', mode='w', encoding='utf-8') as file:
        json.dump(api_to_site, file, indent=4)

def scrape_wallets_from_api(api_domain: str):
    if api_domain == "UNKNOWN":
        print('Skipping UNKNOWN API domain')
        return

    API_URL = "https://" + api_domain + "/api/common/getAssetList"

    """
    Fetch asset list data from the API.
    
    Returns:
        dict: Asset data containing coin names and network information
        
    Raises:
        Exception: If API request fails
    """
    payload = {"type": "BTC", "content": "BitCoin"}
    response = requests.post(API_URL, json=payload)
    initial_data = response.json()
    
    if initial_data["code"] != 200:
        raise Exception(f"API request failed with code {initial_data['code']}: {initial_data['msg']}")

    initial_data = initial_data["data"]

    """
    Create a table of coins with their networks and addresses.
    
    Returns:
        list: List of dictionaries containing coin, network, and address info
    """
    coin_names = initial_data["coinNames"]
    symbol_net = initial_data["symbolNet"]
    
    table = []
    
    # Fetch address data for each coin-network pair
    for coin in coin_names:
        networks = symbol_net.get(coin, [])
        for network in networks:
            payload = {"type": coin, "content": network}
            response = requests.post(API_URL, json=payload)
            secondary_data = response.json()
            
            if secondary_data["code"] == 200:
                symbol_address = secondary_data["data"].get("symbolAddress", "")
                table.append({
                    "coin": coin,
                    "network": network,
                    "address": symbol_address
                })

    api_to_wallet_table[api_domain] = table

    return table
   
def scrape_wallets_from_all_apis():
    with open('logs/api_to_site.json', mode='r', encoding='utf-8') as file:
        api_to_site = json.load(file)
        threads = []
        for api_domain, _sites in api_to_site.items():
            t = Thread(target=scrape_wallets_from_api, args=(api_domain,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
            
    with open('logs/api_to_wallet_table.json', mode='w', encoding='utf-8') as file:
            json.dump(api_to_wallet_table, file, indent=4)

import re

def validate_wallets_from_full_extraction():
    full_data = {}

    with open('logs/full_extraction_data.json', mode='r', encoding='utf-8') as file:
        full_data = json.load(file)
        
    web_apis = full_data.get("web-apis", {})
    for api_domain, api_data in web_apis.items():
        wallets = list(api_data.get("wallets", []))
        validated_wallets = []

        for wallet in wallets:
            wallet_is_valid = False
            wallet_is_supported = False
            address = (wallet.get("address") or "").strip()
            currency_name = (wallet.get("network") or "").lower()

            if currency_name in ('ada', 'arb', 'avax', 'bch', 'bsc', 'btc', 'dash', 'doge', 'eth', 'ltc', 'matic', 'op', 'trx'):
                wallet_is_supported = True

            if address and currency_name and not wallet_is_valid and wallet_is_supported:
                validation_result = coinaddrvalidator.validate(currency_name, address)
                wallet_is_valid = validation_result.valid
                print(f"Validating wallet address: {address} on network: {currency_name} - Result: {validation_result.valid}")

            validated_wallets.append(
                {
                    "address": address,
                    "blockchain": wallet.get("coin"),
                    "network": currency_name,
                    "is_valid": wallet_is_valid,
                    "is_supported": wallet_is_supported
                })

        full_data["web-apis"][api_domain]["wallets"] = validated_wallets
    
    with open('logs/submit_data.json', mode='w', encoding='utf-8') as file:    
        json.dump(full_data, file, indent=4)

def create_full_extraction_data():
    api_to_wallet_table = {}
    api_to_site = {}

    # Full Schema
    """
    webapi = {
        "correlated-sites:" {
            "sitename": {
                "uuid":"unique identifier",
            }
        },
        "wallets": {},
    },
    unidentified-apis: {
        web-api: []
    }
    """

    web_apis = {}
    unidentified_apis = []

    with open("logs/api_to_wallet_table.json") as file:
        api_to_wallet_table = json.load(file)

    with open("logs/api_to_site.json") as file:
        api_to_site = json.load(file)

    for api, wallets in api_to_wallet_table.items():
        for wallet in wallets:
            if wallet.get("network").lower() == "bitcoin":
                wallet["network"] = "btc"
            elif wallet.get("network").lower() == "ethereum" or wallet.get("network").lower() == "erc20":
                wallet["network"] = "eth"
            elif wallet.get("network").lower() == "bnb chain":
                wallet["network"] = "bsc"
            elif wallet.get("network").lower() == "trc20" or wallet.get("network").lower() == "tron" or wallet.get("network").lower() == "usdt-trc":
                wallet["network"] = "trx"
            elif wallet.get("network").lower() == "dogecoin":
                wallet["network"] = "doge"

        web_apis[api] = {
            "correlated-sites": api_to_site.get(api, {}),
            "wallets": wallets
        }

    for api, site_data in api_to_site.items():
        if api not in web_apis:
            web_apis[api] = {
                "correlated-sites": site_data,
                "wallets": {},
                "unidentified-api": True
            }

            unidentified_apis.append(api)

    full_data = {
        "web-apis": web_apis,
        "unidentified-apis": unidentified_apis
    }

    with open("logs/full_extraction_data.json", "w") as file:
        json.dump(full_data, file, indent=4)

def filter_site_duplicates():
    old_site_to_api = {}
    with open('logs/_run1/2a_unreported.txt', mode='r', newline='', encoding='utf-8') as file:
        old_site_to_api = file.read().splitlines()


    genuine_new_sites = []

    with open('logs/unreported.txt', mode='r', newline='', encoding='utf-8') as file:
        new_unreported_sites = file.read().splitlines()

        for line in new_unreported_sites:
            if line not in old_site_to_api:
                genuine_new_sites.append(line)
                print('New unreported site:', line)
            else:
                print('Duplicate unreported site:', line)

    with open('logs/genuine_new_unreported.txt', mode='w', encoding='utf-8') as file:
        for site in genuine_new_sites:
            file.write(site + '\n')


def main():
    extract_unique_domains('logs/urlscan.csv', 'logs/filteredDomains.txt')
    check_sites_reported_bulk()
    get_webapi_from_site()
    create_json_of_web_apis_to_sites()
    scrape_wallets_from_all_apis()
    create_full_extraction_data()
    validate_wallets_from_full_extraction()

main()