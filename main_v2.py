import csv
import json
import re
import socket
import time
import os
import requests
import coinaddrvalidator
from threading import Thread

from dotenv import load_dotenv
load_dotenv()

SCAM_BUSTERS_API_KEY = os.getenv('SCAM_BUSTERS_API_KEY')
URL_SCAN_API_KEY = os.getenv('URL_SCAN_API_KEY')

SCAMBUSTERS_REPORTED_ENDPOINT = "https://scambuster.intelligenceforgood.org/api/check"
SCAMBUSTERS_SUBMIT_ENDPOINT = "https://scambuster.intelligenceforgood.org/api/submit"

URLSCAN_RESULT_ENDPOINT = "https://urlscan.io/api/v1/result/"
URLSCAN_SCAN_ENDPOINT = "https://urlscan.io/api/v1/scan/"
URLSCAN_FETCH_ENDPOINT = "https://urlscan.io/api/v1/search/"

SUPPORTED_NETWORKS = {
    "ada", "arb", "avax", "bch", "bsc", "btc",
    "dash", "doge", "eth", "ltc", "matic", "op", "trx"
}

walletData = {}

# URL SCAN FUNCTIONS

def can_curl_website(site_url: str) -> bool:
    try:
        return bool(socket.gethostbyname(site_url))
    except:
        return False

# Scans a site with urlscan.io and returns the UUID of the scan result, which can be used to retrieve the scan result later. Note: it can take up to 1-2 minutes for the scan result to be available, so you may want to add a delay before trying to retrieve the result.
def scan_site_for_uuid(site_url: str) -> str:
    response = requests.post(
        URLSCAN_SCAN_ENDPOINT,
        headers={"api-key": URL_SCAN_API_KEY, "Content-Type": "application/json"},
        json={"url": f"https://{site_url}", "public": "on"},
        timeout=30
    )
    response.raise_for_status()
    return response.json().get("uuid")

def get_uuid_from_urlscancsv(site_url: str, urlscanFileName: str | None) -> str | None:
    if urlscanFileName is None:
        urlscanFileName = "logs/urlscan.csv"

    with open(urlscanFileName, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)

        first_row = next(reader)
        PageApexDomainIndex = first_row.index("Page Apex Domain")
        ScanURLIndex = first_row.index("Scan URL")

        for siteInfo in reader:
            if siteInfo[PageApexDomainIndex] == site_url:
                scan_url = siteInfo[ScanURLIndex]
                uuid = scan_url.split("/")[4]
                print(f"Found UUID {uuid} for site {site_url} in urlscan CSV")
                return uuid
    return None


# Tries to find the UUID of a urlscan.io scan result for a given site URL by searching urlscan.io results.
def get_uuid_from_site_url(site_url: str) -> str | None:
    uuid_from_csv = get_uuid_from_urlscancsv(site_url, None) 
    
    if uuid_from_csv:
        return uuid_from_csv

    response = requests.get(
        f"{URLSCAN_FETCH_ENDPOINT}?q=domain:{site_url}",
        headers={"api-key": URL_SCAN_API_KEY},
        timeout=30,
    )
    response.raise_for_status()
    results = response.json().get("results", [])
    return results[0].get("_id") if results else None

# Retrieves the urlscan.io result for a given UUID. Note: the result may not be immediately available after scanning, so you may want to add a delay before calling this function after scanning.
def get_urlscan_result_from_uuid(uuid: str) -> dict:
    headers = {"API-Key": URL_SCAN_API_KEY}

    response = requests.get(URLSCAN_RESULT_ENDPOINT + uuid, headers=headers, timeout=30)
    response.raise_for_status()

    return response.json()

# SCAMBUSTERS API FUNCTIONS

def is_site_reported_from_all_sites_txt(site_url: str, allSitesFileName: str) -> bool:
    with open(allSitesFileName, mode='r', newline='', encoding='utf-8') as file:
        for line in file:
            if line.strip() == site_url:
                print(f"Site {site_url} found in all sites text file, treating as reported")
                return True
    return False

# Returns True if the site has already been reported to ScamBusters API, False otherwise
def is_site_reported(site_url: str) -> bool:
    if is_site_reported_from_all_sites_txt(site_url, "logs/all_reported_sites.txt"):
        return True
    
    if site_url == "":
        print("Empty site URL, treating as unreported")
        return False

    headers = {"Authorization": f"Bearer {SCAM_BUSTERS_API_KEY}"}
    params = {"site_url": site_url}

    try:
        response = requests.get(
            SCAMBUSTERS_REPORTED_ENDPOINT,
            headers=headers,
            params=params,
            timeout=30,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error checking if site {site_url} is reported: {e}, treating as unreported")
        time.sleep(2)
        return False

    time.sleep(2)

    return response.json().get("has_wallets", False)
    
def submit_wallets(site_url: str, wallets: list):
    payload = {
        "site_url": site_url,
        "wallets": wallets
    }

    HEADERS = {
        "Authorization": f"Bearer {SCAM_BUSTERS_API_KEY}",
        "Content-Type": "application/json",
    }

    print(payload)

    response = requests.post(SCAMBUSTERS_SUBMIT_ENDPOINT, headers=HEADERS, json=payload)
    print('Response:', response.status_code, response.text)
    time.sleep(5)  # Sleep to avoid hitting rate limits

"""
Example submit payload
{"site_url": "https://scamsite.com", "wallets": [{"address": "0xABC...", "chain": "eth"}]}
"""

def report_sites_from_urlscan_csv(urlscanFileName: str):
    with open(urlscanFileName, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)

        first_row = next(reader)
        PageApexDomainIndex = first_row.index("Page Apex Domain")

        for siteInfo in reader:
            site_url = siteInfo[PageApexDomainIndex]

            if is_site_reported(site_url):
                print(f"Site {site_url} is reported, skipping")
                continue

            print(f"Site {site_url} is unreported, submitting empty wallet data to report the site")
            submit_wallets(site_url, [])

def report_sites_from_blank_json_file(jsonFileName: str):
    with open(jsonFileName, mode='r', newline='', encoding='utf-8') as file:
        data = json.load(file)

        for site_url in data:
            print("site_url:", site_url)
            submit_wallets(site_url, [])

def output_json_to_txt(jsonFileName: str, txtFileName: str):
    with open(jsonFileName, mode='r', newline='', encoding='utf-8') as file:
        data = json.load(file)

        with open(txtFileName, mode='w', newline='', encoding='utf-8') as txt_file:
            for site_url in data:
                txt_file.write(site_url + "\n")

def format_wallets_for_submission(wallets: list) -> list:
    formatted_wallets = []

    for wallet in wallets:
        if not wallet.get("is_valid") or not wallet.get("is_supported"):
            continue

        duplicate = False
        for formatted_wallet in formatted_wallets:
            if wallet.get("address") == formatted_wallet.get("address"):
                duplicate = True
                break
                
        if duplicate:
            continue

        formatted_wallets.append({
            "address": wallet.get("address", ""),
            "chain": wallet.get("network", "")
        })

    return formatted_wallets

def submit_wallets_bulk(inputFileName: str, testMode: bool = False):
    with open(inputFileName, mode='r', newline='', encoding='utf-8') as file:
        file = json.load(file)

        for api_url, data in file.items():
            wallets = data.get("wallets", [])
            correlated_sites = data.get("correlated-sites", [])

            formatted_wallets = format_wallets_for_submission(wallets)

            for site_url in correlated_sites:
                print(f"Submitting wallets for site {site_url}: {formatted_wallets}")

                if not testMode:
                    submit_wallets(site_url, formatted_wallets)
        

# FILE ANALYSIS

# Requires CSV with "Page Apex Domain" column, and outputs a text file with unique sites (one per line)
# Example run method: extract_unique_domains("logs/_run3/urlscan.csv", "logs/unique_sites.json") 
def extract_unique_domains(urlscanFileName: str, outputFileName: str):
   uniqueDomainList = []

   with open(urlscanFileName, mode='r', newline='', encoding='utf-8') as file:
    reader = csv.reader(file)

    first_row = next(reader)
    PageApexDomainIndex = first_row.index("Page Apex Domain")

    for siteInfo in reader:
        if siteInfo[PageApexDomainIndex] not in uniqueDomainList:
            uniqueDomainList.append(siteInfo[PageApexDomainIndex])
            continue

        print('Duplicate site:', siteInfo[PageApexDomainIndex])

    print(len(uniqueDomainList),uniqueDomainList)

    with open(outputFileName, mode='w', encoding='utf-8') as file:
        json.dump(uniqueDomainList, file, indent=4)  # Save the unique domain list as JSON for later use
# extract_unique_domains("logs/_run3/urlscan.csv", "logs/unique_sites.json")

def check_all_curlable_websites(inputFileName: str) -> list:
    curlableSites = []

    with open(inputFileName, mode='r', newline='', encoding='utf-8') as file:
        file = json.load(file)['unreported']  # Assuming the JSON structure has an "unreported" key with the list of sites

        for site in file:
            if can_curl_website(site):
                print('Curlable:', site)
                curlableSites.append(site)
            else:
                print('Not curlable:', site)

    with open("logs/curlable_sites.json", mode='w', encoding='utf-8') as file:
        json.dump(curlableSites, file, indent=4)  # Save the curlable sites list as JSON for later use

    return curlableSites

# Takes JSON of site lists and checks if they are reported or not, then outputs two text files: one for reported sites and one for unreported sites
def check_sites_reported_bulk(inputFileName: str, outputFileName: str):
    isReported = []
    isUnreported = []

    with open(inputFileName, mode='r', newline='', encoding='utf-8') as file:
        file = json.load(file)

        for line in file:
            line = line.strip()

            if line == "":
                print("Empty line in unique sites file, skipping")
                continue

            if is_site_reported(line):
                print('Reported:', line)
                isReported.append(line)
            else:
                print('Unreported:', line)
                isUnreported.append(line)

    outputFile = {
        "reported": isReported,
        "unreported": isUnreported
    }

    with open(outputFileName, mode='w', encoding='utf-8') as file:
        json.dump(outputFile, file, indent=4)  # Save the reported/unreported site lists as JSON for later use
  
# check_sites_reported_bulk("logs/unique_sites.json", "logs/reported_unreported_sites.json")

# Gets unreported sites from the JSON file
def get_unreported_sites(inputFileName: str) -> list:
    unreportedSites = []

    with open(inputFileName, mode='r', newline='', encoding='utf-8') as file:
        file = json.load(file)
        unreportedSites = file.get("unreported", [])

    return unreportedSites

def get_reported_sites(inputFileName) -> list:
    reportedSites = []

    with open(inputFileName, mode='r', newline='', encoding='utf-8') as file:
        file = json.load(file)
        reportedSites = file.get("reported", [])

    return reportedSites

def get_webapi_from_all_sites(unreported_file_name: str, outputFileName: str):
    siteData = {}
    unreportedSites = get_unreported_sites(unreported_file_name)
    print('Total unreported sites:', len(unreportedSites))

    for site in unreportedSites:
        if not can_curl_website(site):
            print('Cannot reach site:', site, 'Skipping API extraction for this site')
            siteData[site] = {
                "api_url": None,
                "uuid": None,
            }
            continue

        print('Progress:' + str(unreportedSites.index(site) + 1) + '/' + str(len(unreportedSites)) + ' - Checking site:', site)
        uuid = get_uuid_from_site_url(site)
        domains = get_urlscan_result_from_uuid(uuid).get('lists', {}).get('domains', [])

        preferred_api = next(
            (d for d in domains if "webapi." in d.lower()),
            None,
        )

        fallback_api = None
        if preferred_api is None:
            fallback_api = next(
            (d for d in domains if any(s in d.lower() for s in ("api.", "pc.", "api1", "api"))),
            None,
            )

        api_domain = preferred_api or fallback_api

        siteData[site] = {
            "api_url": api_domain,
            "uuid": uuid,
        }

        if api_domain:
            print("Unreported site with API domain:", site, "API domain:", api_domain)
        else:
            print("NO API DOMAIN FOUND:", site, domains)

        time.sleep(1)  # Sleep to avoid hitting rate limits

    with open(outputFileName, mode='w', encoding='utf-8') as file:
        json.dump(siteData, file, indent=4) 

def compile_all_sites_into_webapi_json(inputFileName: str, outputFileName: str):
    siteData = {}

    with open(inputFileName, mode='r', newline='', encoding='utf-8') as file:
        file = json.load(file)

        for site, data in file.items():
            api_url = data.get("api_url")

            if not siteData.get(api_url):
                siteData[api_url] = []

            siteData[api_url].append(site)
            
    with open(outputFileName, mode='w', encoding='utf-8') as file:
        json.dump(siteData, file, indent=4)

def scrape_wallets(scrapeType: str, api_url: str, sites) -> list:
    returnWallets = []

    if not can_curl_website(api_url):
        print('Cannot reach API URL:', api_url)
        walletData[api_url] = {
                "wallets": returnWallets,
                "curlable": False,
                "correlated-sites": sites
        }

        return

    if scrapeType == "vipcservice":
        API_URL = "https://" + api_url + "/api/common/getAssetList"

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
        
        # Fetch address data for each coin-network pair
        for coin in coin_names:
            networks = symbol_net.get(coin, [])
            for network in networks:
                payload = {"type": coin, "content": network}
                response = requests.post(API_URL, json=payload)
                secondary_data = response.json()
                
                if secondary_data["code"] != 200:
                    continue

                symbol_address = secondary_data["data"].get("symbolAddress", "")
                returnWallets.append({
                    "coin": coin,
                    "network": network,
                    "address": symbol_address
                })    
        
        walletData[api_url] = {
            "wallets": returnWallets,
            "curlable": True,
            "correlated-sites": sites
        }
    elif scrapeType == "ops-users":
        url = "https://user" + api_url + "/ops/users"

        coinTypes = ["Bitcoin", "Ethereum"]

        payload = "request=getcoin&type=Bitcoin"
        headers = {
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        response = requests.request("POST", url, headers=headers, data=payload)

        print(response.text)
    elif scrapeType == "getAllSetting":
        if api_url is None:
            print("No API URL provided for getAllSetting scrape type")
            return

        ENDPOINT = "https://" + api_url + "/api/common/getAllSetting"

        response = None

        try:
            response = requests.post(ENDPOINT, json={}, verify=False, timeout=10)
        except:
            print('Error reaching API URL:', api_url)
            walletData[api_url] = {
                "wallets": returnWallets,
                "curlable": True,
                "error": "Failed to reach API endpoint",
                "correlated-sites": sites
            }

            return

        data = response.json()
        if data.get("code") != 200:
            print(f"API request failed {data} for URL: {api_url}")
            walletData[api_url] = {
                "wallets": returnWallets,
                "curlable": True,
                "error": "API request failed. Check response data for details.",
                "response_data": data,
                "correlated-sites": sites
            }

            return
        
        walletList = data["data"].get("ASSET_COIN")

        if not walletList:
            print("No wallets found in API response for URL:", api_url)

            walletData[api_url] = {
                "wallets": returnWallets,
                "curlable": True,
                "correlated-sites": sites
            }

            return
        
        """
        Example wallet data format:
        {
                "coinName": "USDT-TRC",
                "coin": "usdt",
                "coinAddress": "TYsan5xmCs399BcZGfjonM1Tp2fwsMGYqk",
                "rechargeNum": 1000,
                "rechargeMax": 10000000,
                "rechargeMin": 1
        },
        """

        for wallet in walletList:
            if not wallet.get("coinAddress"):
                continue

            returnWallets.append({
                "coin": wallet.get("coin", ""),
                "network": wallet.get("coinName", ""),
                "address": wallet.get("coinAddress", "")
            })

        for wallet in returnWallets:
            network_lower = wallet.get("network", "").lower()
            
            # Network mapping with keywords
            network_mapping = {
                "btc": ["bitcoin"],
                "eth": ["ethereum", "erc", "usdt-erc"],
                "bsc": ["bnb chain"],
                "trx": ["trc", "tron", "usdt-trc", "trc20"],
                "doge": ["doge", "dogecoin"]
            }
            
            for network_code, keywords in network_mapping.items():
                if any(keyword in network_lower for keyword in keywords):
                    wallet["network"] = network_code
                    break
            
            if "usdt" or "usdc" in wallet.get("network").lower():
                identified_networks = identify_wallet_address(wallet.get("address", ""))
                wallet["network"] = identified_networks[0] if identified_networks else wallet["network"]

    print('Finished scraping wallets for API URL:', api_url, 'Scraped wallets:', returnWallets)
    walletData[api_url] = {
        "wallets": returnWallets,
        "correlated-sites": sites,
        "curlable": True
    }

    return returnWallets

def scrape_all_wallets(scrapeType: str, webapi_json_file_name: str, outputFileName: str):
    with open(webapi_json_file_name, mode='r', newline='', encoding='utf-8') as file:
        file = json.load(file)

        threads = []

        for api_url, sites in file.items():
            t = Thread(target=scrape_wallets, args=(scrapeType, api_url,sites))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    with open(outputFileName, mode='w', encoding='utf-8') as file:
        json.dump(walletData, file, indent=4)

def _extract_network_key(network: str, blockchain: str) -> str:
    raw = ((network or "").strip() or (blockchain or "").strip()).lower()
    if raw in SUPPORTED_NETWORKS:
        return raw

    # Handles values like "USDT-TRC", "ERC-20", etc.
    for part in raw.replace("_", "-").split("-"):
        if part in SUPPORTED_NETWORKS:
            return part

    return raw

def identify_wallet_address(address: str) -> list[str]:
    """
    Identify which cryptocurrency network(s) a wallet address could belong to.
    Supports: btc, eth, trx, doge.
    """

    patterns: dict[str, list[re.Pattern]] = {
        # Bitcoin: Legacy (1...), SegWit P2SH (3...), Native SegWit (bc1q/bc1p)
        "btc": [
            re.compile(r"^1[a-km-zA-HJ-NP-Z1-9]{25,34}$"),
            re.compile(r"^3[a-km-zA-HJ-NP-Z1-9]{25,34}$"),
            re.compile(r"^bc1q[a-z0-9]{38,58}$"),
            re.compile(r"^bc1p[a-z0-9]{58}$"),
        ],
        # Ethereum: 0x prefix, 40 hex characters
        "eth": [
            re.compile(r"^0x[0-9a-fA-F]{40}$"),
        ],
        # Tron: starts with T, 34 chars, Base58
        "trx": [
            re.compile(r"^T[a-km-zA-HJ-NP-Z1-9]{33}$"),
        ],
        # Dogecoin: starts with D or A (multisig)
        "doge": [
            re.compile(r"^D[5-9A-HJ-NP-U][a-km-zA-HJ-NP-Z1-9]{24,33}$"),
            re.compile(r"^A[a-km-zA-HJ-NP-Z1-9]{25,34}$"),
        ],
    }

    address = address.strip()
    return [
        chain
        for chain, regexes in patterns.items()
        if any(regex.match(address) for regex in regexes)
    ]

def validate_wallet_data(inputFileName: str, outputFileName: str):
    with open(inputFileName, mode="r", encoding="utf-8") as file:
        full_data = json.load(file)

    for api_domain, api_data in full_data.items():
        wallets = api_data.get("wallets", [])
        validated_wallets = []

        for wallet in wallets:
            address = (wallet.get("address") or "").strip()
            blockchain = (wallet.get("coin") or wallet.get("blockchain") or "").strip().lower()
            network_key = _extract_network_key(wallet.get("network", ""), blockchain)

            is_supported = network_key in SUPPORTED_NETWORKS
            is_valid = False

            if address and is_supported:
                try:
                    if network_key == "btc" or network_key == "doge" or network_key == "trx" or network_key == "eth":
                        # For Bitcoin and Dogecoin, we can use the identify_wallet_address function to check if the address matches the expected format for the identified network
                        is_valid = network_key in identify_wallet_address(address)
                    else:
                        is_valid = coinaddrvalidator.validate(network_key, address).valid


                except Exception:
                    is_valid = False

            print(f"Validation result for address {address} on network {network_key}: is_valid={is_valid}, is_supported={is_supported}")

            validated_wallets.append(
                {
                    "address": address,
                    "blockchain": blockchain,
                    "network": network_key,
                    "is_valid": is_valid,
                    "is_supported": is_supported,
                }
            )

        full_data[api_domain]["wallets"] = validated_wallets

    with open(outputFileName, mode="w", encoding="utf-8") as file:
        json.dump(full_data, file, indent=4)

def append_sites_to_txt(json_path: str, txt_path: str) -> int:
    """
    Read a JSON file with 'reported' and 'unreported' lists,
    and append all sites to a text file (one per line).

    Returns the total number of sites appended.
    """
    with open(json_path, "r") as f:
        data = json.load(f)

    sites = data.get("reported", []) + data.get("unreported", [])

    with open(txt_path, "a") as f:
        for site in sites:
            f.write(site + "\n")

    return len(sites)

def main():
    # extract_unique_domains("logs/urlscan.csv", "logs/unique_sites.json")
    # check_sites_reported_bulk("logs/unique_sites.json", "logs/reported_unreported_sites.json")
    # check_all_curlable_websites("logs/reported_unreported_sites.json")
    
    # get_webapi_from_all_sites("logs/reported_unreported_sites.json", "logs/sites_webapi_with_uuids.json")
    # compile_all_sites_into_webapi_json("logs/sites_webapi_with_uuids.json", "logs/webapi_final.json")
    # scrape_all_wallets("getAllSetting", "logs/webapi_final.json", "logs/scraped_wallets.json")
    # validate_wallet_data("logs/scraped_wallets.json", "logs/validated_wallets.json")
    submit_wallets_bulk("logs/validated_wallets.json", False)

    """
    # report_sites_from_blank_json_file("logs/curlable_sites.json")
    # report_sites_from_urlscan_csv("logs/urlscan.csv")
    # append_sites_to_txt("logs/reported_unreported_sites.json", "logs/all_reported_sites.txt")
    """
    


main()