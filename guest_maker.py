# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════╗
║  NEW UPDATE — guest_maker.py                         ║
║  Create & Register Guest accounts                    ║
╚══════════════════════════════════════════════════════╝
"""
import json
import os
import time
import random
import requests
import urllib3
from datetime import datetime

from config import (
    REGIONS, GUEST_REGISTER_URL, GUEST_TOKEN_URL,
    HMAC_SECRET, MAJOR_LOGIN_PAYLOAD_HEX,
    OLD_OPEN_ID, OLD_ACCESS_TOKEN, OLD_SIG_MD5,
    GARENA_HEADERS, LOGIN_HEADERS,
    ACTIVATED_FILE, DATA_DIR,
)
from crypto_engine import aes_encrypt_hex, hmac_sign, xor_encode_open_id, build_protobuf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
R = "\033[1;91m"; G = "\033[1;92m"; Y = "\033[1;93m"
C = "\033[1;96m"; W = "\033[1;97m"; M = "\033[1;95m"
O = "\033[1;38;5;214m"; D = "\033[0m"


def _session():
    s = requests.Session()
    a = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=1)
    s.mount("https://", a)
    s.mount("http://", a)
    return s


def generate_password(prefix="ELHERD"):
    suffix = ''.join(random.choices("0123456789ABCDEFabcdef", k=8))
    return f"{prefix}{suffix}"


def generate_name():
    parts = [
        random.choice(["FF", "FN", "Bz", "NJ", "Kz", "Xd", "Rx", "Gx"]),
        random.choice(["King", "Pro", "Boss", "Hero", "Star", "Fire", "Dark"]),
        str(random.randint(10, 999)),
    ]
    return "".join(parts)


# ═══════════════════════════════════════════════════════════════════════
#  Step 1: Create Guest Account
# ═══════════════════════════════════════════════════════════════════════

def create_guest(password):
    """Register a new guest account. Returns {uid: ...} or None."""
    data_str = f"password={password}&client_type=2&source=2&app_id=100067"
    sig = hmac_sign(data_str)
    headers = {
        **GARENA_HEADERS,
        "Authorization": "Signature " + sig,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        r = requests.post(GUEST_REGISTER_URL, headers=headers, data=data_str,
                          timeout=30, verify=False)
        r.raise_for_status()
        j = r.json()
        if "uid" in j:
            return j
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════
#  Step 2: Get Guest Token
# ═══════════════════════════════════════════════════════════════════════

def get_guest_token(uid, password):
    """Get access_token and open_id. Returns (access_token, open_id) or (None, None)."""
    body = {
        "uid": str(uid),
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": HMAC_SECRET,
        "client_id": "100067",
    }
    headers = {
        **GARENA_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "100067.connect.garena.com",
    }
    try:
        r = requests.post(GUEST_TOKEN_URL, headers=headers, data=body,
                          timeout=30, verify=False)
        r.raise_for_status()
        j = r.json()
        if "open_id" in j:
            return j["access_token"], j["open_id"]
    except Exception:
        pass
    return None, None


# ═══════════════════════════════════════════════════════════════════════
#  Step 3: MajorRegister
# ═══════════════════════════════════════════════════════════════════════

def major_register(access_token, open_id, name, region_code="ME"):
    """Register the account in game server. Returns True/False."""
    cfg = REGIONS.get(region_code, REGIONS["ME"])
    login_host = cfg["login_host"]
    url = f"https://{login_host}/MajorRegister"
    lang = cfg["lang"]
    field14 = xor_encode_open_id(open_id)

    proto = build_protobuf({
        1: name, 2: access_token, 3: open_id,
        5: 102000007, 6: 4, 7: 1, 13: 1,
        14: field14, 15: lang, 16: 1, 17: 1,
    })
    encrypted = bytes.fromhex(aes_encrypt_hex(proto.hex()))

    headers = {
        **LOGIN_HEADERS,
        "Authorization": "Bearer",
        "Expect": "100-continue",
        "Host": login_host,
    }
    try:
        r = requests.post(url, headers=headers, data=encrypted, verify=False, timeout=30)
        return r.status_code == 200
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════
#  Step 4: MajorLogin
# ═══════════════════════════════════════════════════════════════════════

def major_login(access_token, open_id, region_code="ME"):
    """MajorLogin to get JWT. Returns raw response bytes or None."""
    cfg = REGIONS.get(region_code, REGIONS["ME"])
    login_host = cfg["login_host"]
    url = f"https://{login_host}/MajorLogin"

    payload = bytes.fromhex(MAJOR_LOGIN_PAYLOAD_HEX)
    payload = payload.replace(OLD_OPEN_ID, open_id.encode())
    payload = payload.replace(OLD_ACCESS_TOKEN, access_token.encode())
    encrypted = bytes.fromhex(aes_encrypt_hex(payload.hex()))

    headers = {
        **LOGIN_HEADERS,
        "Authorization": "Bearer",
        "Expect": "100-continue",
        "Host": login_host,
    }
    try:
        r = requests.post(url, headers=headers, data=encrypted, verify=False, timeout=30)
        if r.status_code == 200 and len(r.content) > 0:
            return r.content
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════
#  Extract JWT from MajorLogin response
# ═══════════════════════════════════════════════════════════════════════

def extract_jwt(raw_response):
    """Extract JWT token from MajorLogin raw response."""
    try:
        text = raw_response.decode("latin-1", errors="ignore")
        jwt_start = text.find("eyJ")
        if jwt_start != -1:
            jwt = text[jwt_start:]
            dot1 = jwt.find(".")
            dot2 = jwt.find(".", dot1 + 1)
            if dot2 != -1:
                return jwt[:dot2 + 44]
    except Exception:
        pass
    return None


def extract_account_id(jwt_token):
    """Extract account_id from JWT payload."""
    import base64
    try:
        parts = jwt_token.split(".")
        payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return str(data.get("account_id", data.get("external_id", "N/A")))
    except Exception:
        return "N/A"


# ═══════════════════════════════════════════════════════════════════════
#  Full Pipeline: Create + Register
# ═══════════════════════════════════════════════════════════════════════

def create_one_account(region_code="ME", pw_prefix="ELHERD"):
    """Full pipeline: create guest → get token → register → login. Returns entry dict or None."""
    pw = generate_password(pw_prefix)
    name = generate_name()

    # Step 1: Create guest
    guest = create_guest(pw)
    if not guest:
        return None
    uid = guest["uid"]

    # Step 2: Get token
    access_token, open_id = get_guest_token(uid, pw)
    if not access_token:
        return None

    # Step 3: Register in game
    ok = major_register(access_token, open_id, name, region_code)
    if not ok:
        return None

    # Step 4: MajorLogin to get JWT
    raw = major_login(access_token, open_id, region_code)
    jwt = extract_jwt(raw) if raw else None
    account_id = extract_account_id(jwt) if jwt else "N/A"

    entry = {
        "uid": uid,
        "password": pw,
        "name": name,
        "account_id": account_id,
        "region": region_code,
        "access_token": access_token,
        "open_id": open_id,
        "jwt_token": jwt or "",
        "activated": False,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return entry


def save_account(entry, filepath):
    """Append account to the specified JSON file."""
    data = []
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []
    data.append(entry)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def create_accounts_batch(count, region_code="ME", pw_prefix="ELHERD", speed_mul=1.0):
    """Create multiple accounts sequentially."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(DATA_DIR, f"guest_accounts_{timestamp}.json")
    print(f"  {C}📂 Output file: {os.path.basename(filepath)}{D}")
    results = []
    for i in range(count):
        print(f"  {Y}[{i+1}/{count}]{D} Creating account...", end=" ")
        entry = create_one_account(region_code, pw_prefix)
        if entry:
            save_account(entry, filepath)
            results.append(entry)
            print(f"{G}✅ {entry['name']} | UID: {entry['uid']} | ID: {entry['account_id']}{D}")
        else:
            print(f"{R}❌ Failed{D}")
        time.sleep(random.uniform(1.0, 2.5) * speed_mul)
    return results


if __name__ == "__main__":
    print(f"\n{O}═══ Guest Maker Test ═══{D}")
    entry = create_one_account("ME")
    if entry:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(DATA_DIR, f"guest_accounts_{timestamp}.json")
        save_account(entry, filepath)
        print(f"\n{G}✅ Account created and saved to {os.path.basename(filepath)}:{D}")
        print(json.dumps(entry, indent=2, ensure_ascii=False))
    else:
        print(f"{R}❌ Failed to create account{D}")
