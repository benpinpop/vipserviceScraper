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

SCAM_BUSTERS_API_KEY = os.getenv('SCAM_BUSTERS_API_KEY')
URL_SCAN_API_KEY = os.getenv('URL_SCAN_API_KEY')

SCAMBUSTERS_REPORTED_ENDPOINT = "https://scambuster.intelligenceforgood.org/api/check"
SCAMBUSTERS_SUBMIT_ENDPOINT = "https://scambuster.intelligenceforgood.org/api/submit"

URLSCAN_RESULT_ENDPOINT = "https://urlscan.io/api/v1/result/"
URLSCAN_SCAN_ENDPOINT = "https://urlscan.io/api/v1/scan/"
URLSCAN_FETCH_ENDPOINT = "https://urlscan.io/api/v1/search/"

# URL SCAN FUNCTIONS

# Scans a site with urlscan.io and returns the UUID of the scan result, which can be used to retrieve the scan result later. Note: it can take up to 1-2 minutes for the scan result to be available, so you may want to add a delay before trying to retrieve the result.
def scan_site_for_uuid(site_url: str) -> str:
    headers = {"API-Key": URL_SCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": "https://" + site_url, "public": "on"}

    response = requests.post(URLSCAN_SCAN_ENDPOINT, headers=headers, json=data, timeout=30)
    response.raise_for_status()

    response = response.json()
    return response.get("uuid")

# Tries to find the UUID of a urlscan.io scan result for a given site URL by searching urlscan.io results.
def get_uuid_from_site_url(site_url: str) -> str:
    headers = {"API-Key": URL_SCAN_API_KEY}

    response = requests.get(URLSCAN_FETCH_ENDPOINT + "?q=domain:" + site_url, headers=headers, timeout=30)
    response.raise_for_status()

    response = response.json()
    
    if len(response.get("results")) == 0:
        return None
    
    response = response.get("results")[0]
    return response.get("_id")

# Retrieves the urlscan.io result for a given UUID. Note: the result may not be immediately available after scanning, so you may want to add a delay before calling this function after scanning.
def get_urlscan_result_from_uuid(uuid: str) -> dict:
    headers = {"API-Key": URL_SCAN_API_KEY}

    response = requests.get(URLSCAN_RESULT_ENDPOINT + uuid, headers=headers, timeout=30)
    response.raise_for_status()

    return response.json()

# SCAMBUSTERS API FUNCTIONS

# Returns True if the site has already been reported to ScamBusters API, False otherwise
def is_site_reported(site_url: str) -> bool:
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

# Takes JSON of site lists and checks if they are reported or not, then outputs two text files: one for reported sites and one for unreported sites
def check_sites_reported_bulk(inputFileName: str, outputFileName: str):
    isReported = []
    isUnreported = []

    with open(inputFileName, mode='r', newline='', encoding='utf-8') as file:
        file = json.load(file)

        for line in file:
            line = line.strip()

            if is_site_reported(line):
                print('Reported:', line)
                isReported.append(line)
            else:
                print('Unreported:', line)
                isUnreported.append(line)
            time.sleep(2)

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