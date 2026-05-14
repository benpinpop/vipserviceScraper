import time

import requests


import hashlib
import time
import requests

import hashlib
import time
import requests

DEFAULT_TOKEN = "tfleat3tbdtdbtc2"

def md5(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()

def build_headers(base_url: str, referer_path: str = "/", uuid: str = "", token: str = DEFAULT_TOKEN, locale: str = "en") -> dict:
    timestamp = str(int(time.time() * 1000))
    auth_token = md5(token + md5(timestamp + uuid))

    return {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": locale,
        "Content-Type": "application/json",
        "e-token-me": uuid,
        "e-auth-token": auth_token,
        "Origin": base_url,
        "Referer": f"{base_url}{referer_path}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    }, timestamp

def make_request(base_url: str, endpoint: str, referer_path: str = "/", uuid: str = "", token: str = DEFAULT_TOKEN, locale: str = "en", extra_data: dict = None):
    headers, timestamp = build_headers(base_url, referer_path, uuid, token, locale)
    data = extra_data or {}
    data["time"] = int(timestamp)

    response = requests.post(f"{base_url}{endpoint}", headers=headers, json=data)
    return response

SEND_EMAIL = "/api/login/sendEmail"
REGISTER = "/api/login/register"
LOGIN = "/api/login/index"
GET_RECHARGE = "/api/account/getRechInfo"

def send_email(site, email):
    response = make_request(f"https://{site}", SEND_EMAIL, extra_data={"email": email, "t": 1})

    if response.status_code != 200:
        raise Exception(f"Failed to send email: {response.status_code} - {response.text}")
    
    # RESPONSE DATA
    """
    {"code":200,"message":"Success","data":{"code":"DGKN"}}"""

    data = response.json()
    print(data)
    # get code from data
    code = data.get("data", {}).get("code")
    
    if not code:
        raise Exception(f"Failed to get code from response: {data}")

    return code

def register(site, email, code):
    resp = make_request(f"https://{site}", REGISTER, referer_path="/register",
                        extra_data={"code": 8, "phone": "", "email": email, "password": "password1",
                                    "confirmPassword": "password1", "emailcode": code, "validcode": ""})
    data = resp.json()
    if data.get("code") != 200:
        raise Exception(f"Failed to register: {data}")
    return True


def login(site,email,password):
    # {"email":"aurian.ruben@minafter.com","password":"password1","t":2,"time":1778355923952}

    data = make_request(f"https://{site}", LOGIN, extra_data={"email": email, "password": password, "t": 2})
    data = data.json()
    if data.get("code") != 200:
        raise Exception(f"Failed to login: {data}")

    """
    {
    "code": 200,
    "message": "Success",
    "data": {
        "token": "ab941cea260a7b090001595f62439af8",
        "me": "1b2aace2c22c2a8855ad0f35eb813192"
    }
}
    extract token and me from data
    """
    token = data.get("data", {}).get("token")
    me = data.get("data", {}).get("me")

    if not token or not me:
        raise Exception(f"Failed to get token or me from response: {data}")
    
    return token, me

def get_recharge_info(site, token, me):
    data = make_request(f"https://{site}", GET_RECHARGE, referer_path="/account", uuid=me, token=token)
    data = data.json()
    if data.get("code") != 200:
        raise Exception(f"Failed to get recharge info: {data}")
    
    return data.get("data")

"""
Example recharge info data:
{'rlist': [], 'git_num': None, 'lastRecharge': None, 'account': {'rand_id': 41568345, 'total': '0.00000000', 'balance': '0.00000000', 'freeze': '0.00000000', 'income': '0.00000000', 'recharge': '0.00000000', 'cash': '0.00000000', 'commission': '0.00000000', 'gift': '0.00000000', 'expand': '0.00000000', 'contract': '0.00000000', 'contract_freeze': '0.00000000', 'contract_income': '0.00000000', 'micro': '0.00000000', 'micro_freeze': '0.00000000', 'micro_income': '0.00000000'}, 'minrecharge': None, 'currency': [{'id': 2, 'name': 'USDC', 'pay_type': 'currency', 'show_name': 'USDT', 'network': 'TRC20', 'img_url': '//imge2024.oss-us-east-1.aliyuncs.com/202512/02112911-86606067134058977.png', 'type': 'usdt_trc_20', 'content': {'type': 'USDC', 'account': 'TVaKNoEbMXveCBc2qfpUjPZyUD9gQzZJV9'}}, {'id': 3, 'name': 'USDT-ERC20', 'pay_type': 'currency', 'show_name': 'USDT', 'network': 'ERC20', 'img_url': '//imge2024.oss-us-east-1.aliyuncs.com/scheme/20240723/905de572bf40044e9f773d18b4866a04.png', 'type': 'usdt_erc_20', 'content': {'type': 'USDT-ERC', 'account': '0x698f0c8b1de371ccc6ec95c4119ac962e1d2b7a6'}}, {'id': 4, 'name': 'BTC', 'pay_type': 'currency', 'show_name': 'BTC', 'network': 'BTC', 'img_url': '//imge2024.oss-us-east-1.aliyuncs.com/202504/08104156-87586017525945338.png?attname=BTC.png', 'type': 'btc', 'content': {'type': 'USDT-ERC20', 'account': 'bc1pr6u6p7lzcpuhzyrqtfpdx5748asyrsx6yvg6mpp75n9yx4kwfa7qlz9px9'}}, {'id': 5, 'name': 'ETH', 'pay_type': 'currency', 'show_name': 'ETH', 'network': 'ERC20', 'img_url': '//imge2024.oss-us-east-1.aliyuncs.com/202504/08104126-13312175098490345.png?attname=ETH.png', 'type': 'eth', 'content': {'type': 'USDT-ERC20', 'account': '0x698f0c8b1de371ccc6ec95c4119ac962e1d2b7a6'}}, {'id': 8, 'name': 'USDC', 'pay_type': 'currency', 'show_name': 'USDC', 'network': 'ERC20', 'img_url': '//imge2024.oss-us-east-1.aliyuncs.com/202504/08104041-32373986716958884.png?attname=USDC.png', 'type': 'usdc', 'content': {'type': 'USDT-ERC20', 'account': '0xd81d89834d13a765c1e9b28e6cd0b278fa3cb3049de3958ee86dc5bc32841d08'}}, {'id': 9, 'name': 'SOL', 'pay_type': 'currency', 'show_name': 'SOL', 'network': 'TRC20', 'img_url': '//by-fsm.oss-ap-southeast-1.aliyuncs.com/0d/8e9a185773da474955639b5fc82808.png?attname=solana-sol-logo.png', 'type': 'sol', 'content': {'type': 'USDT-ERC20', 'account': '4yx8YG9QBs5YwuGPt45wLWfeJxD4pkug3Xxt5Xwyhuvi'}}]}
"""

"""
Example return format
"""

def extract_wallet_addresses(recharge_info):
    print(recharge_info)

EMAIL = "hellothere@minafter.com"
PASSWORD = "password1"

code = send_email("kracexcharge.it.com", EMAIL)
print(code)
success = register("kracexcharge.it.com", EMAIL, code)
token, me = login("kracexcharge.it.com", EMAIL, PASSWORD)
print(f"Token: {token}, Me: {me}")
print(get_recharge_info("kracexcharge.it.com", token, me))

