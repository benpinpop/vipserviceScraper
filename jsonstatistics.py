import json

totalWalletAddresses = []
with open("logs/api_to_wallet_table.json", mode='r', encoding='utf-8') as file:
    api_to_wallet_table = json.load(file)

    for api_domain, wallets in api_to_wallet_table.items():
        for wallet in wallets:
            if wallet["network"].lower() == "solana" or wallet["network"].lower() == "base":
                continue

            if wallet["address"] not in totalWalletAddresses:
                totalWalletAddresses.append(wallet["address"])

    print("Total unique wallet addresses:", len(totalWalletAddresses))