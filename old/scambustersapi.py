import json
from settings import configuration
import requests


BASE_URL = "https://scambuster.intelligenceforgood.org/api/check"
API_KEY = configuration['SCAM_BUSTERS_API_KEY']

def is_site_reported(site_url: str):
  headers = {"Authorization": f"Bearer {API_KEY}"}
  params = {"site_url": site_url}

  response = requests.get(BASE_URL, headers=headers, params=params, timeout=30)
  response.raise_for_status()

  response = response.json()
  print(response)
  if response.get("has_wallets"):
     return True
  else:
     return False