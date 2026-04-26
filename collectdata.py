import json

totalWalletAddresses = []
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
