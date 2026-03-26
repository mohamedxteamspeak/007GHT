# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════╗
║  NEW UPDATE — config.py                              ║
║  Region configs, AES keys, endpoint templates        ║
║  Auto-updated from koolchi traffic analysis          ║
╚══════════════════════════════════════════════════════╝
"""
import os, sys

# ─── Fix Windows encoding ────────────────────────────────────────────
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")
KOOLCHI_DIR = os.path.join(PROJECT_ROOT, "koolchi", "captured_data")
os.makedirs(DATA_DIR, exist_ok=True)

ACTIVATED_FILE = os.path.join(DATA_DIR, "activated.json")

# ─── AES Keys ─────────────────────────────────────────────────────────
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ─── HMAC Secret ──────────────────────────────────────────────────────
HMAC_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
HMAC_SECRET_BYTES = bytes.fromhex(
    "32656534343831396539623435393838"
    "34353134313036376232383136323138"
    "37346430643564376166396438663765"
    "30306331653534373135623764316533"
)

# ─── XOR Keystream for open_id encoding (MajorRegister) ──────────────
XOR_KEYSTREAM = [
    0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31,
    0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30,
]

# ─── Region Configuration (UPDATED with ggpolarbear.com for ME) ──────
REGIONS = {
    "ME": {
        "lang": "ar",
        "guest_url": "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
        "login_host": "loginbp.ggpolarbear.com",
        "client_url": "https://clientbp.ggpolarbear.com/",
        "client_host": "clientbp.ggpolarbear.com",
    },
    "IND": {
        "lang": "hi",
        "guest_url": "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
        "login_host": "loginbp.common.ggbluefox.com",
        "client_url": "https://client.ind.freefiremobile.com/",
        "client_host": "client.ind.freefiremobile.com",
    },
    "BD": {
        "lang": "bn",
        "guest_url": "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
        "login_host": "loginbp.ggblueshark.com",
        "client_url": "https://clientbp.ggblueshark.com/",
        "client_host": "clientbp.ggblueshark.com",
    },
    "PK": {
        "lang": "ur",
        "guest_url": "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
        "login_host": "loginbp.ggblueshark.com",
        "client_url": "https://clientbp.ggblueshark.com/",
        "client_host": "clientbp.ggblueshark.com",
    },
    "ID": {
        "lang": "id",
        "guest_url": "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
        "login_host": "loginbp.ggblueshark.com",
        "client_url": "https://clientbp.ggblueshark.com/",
        "client_host": "clientbp.ggblueshark.com",
    },
    "TH": {
        "lang": "th",
        "guest_url": "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
        "login_host": "loginbp.common.ggbluefox.com",
        "client_url": "https://clientbp.common.ggbluefox.com/",
        "client_host": "clientbp.common.ggbluefox.com",
    },
    "VN": {
        "lang": "vi",
        "guest_url": "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
        "login_host": "loginbp.ggblueshark.com",
        "client_url": "https://clientbp.ggblueshark.com/",
        "client_host": "clientbp.ggblueshark.com",
    },
    "BR": {
        "lang": "pt",
        "guest_url": "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
        "login_host": "loginbp.ggblueshark.com",
        "client_url": "https://client.us.freefiremobile.com/",
        "client_host": "client.us.freefiremobile.com",
    },
}

# ─── Guest Registration URL ──────────────────────────────────────────
GUEST_REGISTER_URL = "https://100067.connect.garena.com/oauth/guest/register"
GUEST_TOKEN_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"

# ─── Payload template (from garena_api.py — MajorLogin) ──────────────
MAJOR_LOGIN_PAYLOAD_HEX = (
    "1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07"
    "312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d32332028"
    "4e32473438482f373030323530323234294a0848616e6468656c645207416e64726f6964"
    "5a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20"
    "564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d2920363430"
    "92010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d63"
    "6562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31"
    "322e313335aa0102656eb201203939366136323964626364623339363462653662363937"
    "386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e672053"
    "4d2d473935354eea014066663930633037656239383135616633306134336234613966363"
    "031393531366530653463373033623434303932353136643064656661346365663531663261"
    "f00101ca0207416e64726f6964d2020457494649ca0320373432386232353364656663313"
    "634303138633630346131656262666562646"
    "6e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b07980"
    "4daa907c80403d204262f646174612f6170702f636f6d2e6474732e66726565666972657"
    "4682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465"
    "376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656"
    "669726574682d312f626173652e61706bf00403f804018a050233329a050a323031393131"
    "38363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea050761"
    "6e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43"
    "676542557562555551317375746d525536634e30524f375145314148"
    "6e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d"
    "8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d574166575"
    "45a065f2a091d6a0d5033"
)

# Template markers
OLD_OPEN_ID = b"996a629dbcdb3964be6b6978f5d814db"
OLD_ACCESS_TOKEN = b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
OLD_SIG_MD5 = b"7428b253defc164018c604a1ebbfebdf"

# ─── Standard Headers ─────────────────────────────────────────────────
GARENA_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
    "Accept-Encoding": "gzip",
    "Connection": "Keep-Alive",
}

LOGIN_HEADERS = {
    "X-Unity-Version": "2018.4.11f1",
    "ReleaseVersion": "OB52",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-GA": "v1 1",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)",
    "Connection": "Keep-Alive",
}

CLIENT_HEADERS = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB52",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
    "Connection": "close",
    "Accept-Encoding": "gzip, deflate, br",
}

# ─── Known Royale Events (from LIVE koolchi captures 2026-03-24) ─────
# Each event has exact Protobuf fields captured from real traffic
KNOWN_ROYALES = {
    87: {
        "name": "🎰 Unlimited Gacha (ME)",
        "box_id": 526,     # field 3
        "currency": 5,     # field 4 = diamonds
        "default_count": 1, # from royale_1_SPIN_87
        "extra_fields": {},  # no extra fields
        "raw_hex": "08571001188e0420056802",  # verified 1-spin payload
    },
    93: {
        "name": "🎡 Chest Wheel",
        "box_id": 471,     # field 3  (NOT 526!)
        "currency": 2,     # field 4 = 2 (special currency)
        "default_count": 2, # from royale_2_SPIN_93
        "extra_fields": {10: 10},  # field 10 = 10
        "raw_hex": "085d100218d7032002500a6802",  # verified 2-spin payload
    },
    5: {
        "name": "💰 Gold Chest",
        "box_id": 521,     # field 3  (NOT 50!)
        "currency": 1,     # field 4 = 1 (gold)
        "default_count": 1, # from royale_1_SPIN_5
        "extra_fields": {12: 300, 13: 1},  # field 12 = 300, field 13 = 1
        "raw_hex": "08051001188904200160ac026801",  # verified 1-spin payload
    },
}

# ─── Items Database (from user + koolchi raw_traffic asset IDs) ───────
# Used to detect what items accounts receive from Royale spins
# Items are organized by tiers: GRAND_PRIZE > EPIC > RARE > COMMON

ITEMS_DB = {
    # ═══ GRAND PRIZES (Ultra Rare) ═══════════════════════════════════
    710052023: "🏆 Shadow Walker Bundle (GRAND PRIZE)",
    908052009: "🏆 MotoBiker Shadow Walker (GRAND PRIZE)",
    907105209: "🏆 Scar Shadow Scars (GRAND PRIZE)",

    # ═══ EPIC ITEMS ══════════════════════════════════════════════════
    907104202: "⭐ M41 Sunrise Realm",
    907103324: "⭐ MAG-7 Shadow Rouge",
    907104019: "⭐ P90 Bunny's Order",
    905000065: "⭐ Parachute (Epic)",
    907104714: "⭐ P90 24K Pitty",

    # ═══ FROM KOOLCHI RAW TRAFFIC (asset IDs found) ═════════════════
    # Clothing items from traffic captures
    203052018: "👕 Cloth Top",
    204052018: "👖 Cloth Bottom",
    205052018: "👟 Cloth Shoes",
    211052021: "🎭 Accessory A",
    211052022: "🎭 Accessory B",

    # Callsign & Icons
    819160430: "🔖 Callsign Banner",
    819460430: "🔖 Callsign Banner B",
    819660430: "🔖 Callsign Banner C",

    # Loadout items
    907194911: "🎮 Loadout Item",

    # Avatar frames (9xx series)
    901049001: "🖼️ Avatar Frame",
    901049002: "🖼️ Avatar Frame B",
    901049003: "🖼️ Avatar Frame C",
    901049004: "🖼️ Avatar Frame D",
    901049007: "🖼️ Avatar Frame E",
    901049008: "🖼️ Avatar Frame F",
    901049010: "🖼️ Avatar Frame G",
    901049011: "🖼️ Avatar Frame H",
    901049012: "🖼️ Avatar Frame I",
    901049013: "🖼️ Avatar Frame J",
    901049014: "🖼️ Avatar Frame K",
    901049019: "🖼️ Avatar Frame L",
    901049020: "🖼️ Avatar Frame M",
    901050001: "🖼️ Avatar Card A",
    901050003: "🖼️ Avatar Card B",
    901050007: "🖼️ Avatar Card C",
    901050008: "🖼️ Avatar Card D",
    901050016: "🖼️ Avatar Card E",
    902049001: "👤 Avatar A",
    902049002: "👤 Avatar B",
    902049003: "👤 Avatar C",
    902049004: "👤 Avatar D",
    902049007: "👤 Avatar E",
    902049008: "👤 Avatar F",
    902049010: "👤 Avatar G",
    902049011: "👤 Avatar H",
    902049012: "👤 Avatar I",
    902049013: "👤 Avatar J",
    902049021: "👤 Avatar K",
    902050001: "👤 Avatar Pack A",
    902050002: "👤 Avatar Pack B",
    902050003: "👤 Avatar Pack C",
    902050004: "👤 Avatar Pack D",
    902050005: "👤 Avatar Pack E",
    902050006: "👤 Avatar Pack F",
    902050007: "👤 Avatar Pack G",
    902050008: "👤 Avatar Pack H",
    902050009: "👤 Avatar Pack I",
    902050010: "👤 Avatar Pack J",
    902050013: "👤 Avatar Pack K",
    902050014: "👤 Avatar Pack L",
    902050020: "👤 Avatar Pack M",
    910050001: "🎵 Emote/Voice",
}

# Grand prizes (IDs that trigger special alert)
GRAND_PRIZE_IDS = {710052023, 908052009, 907105209}
# Epic items
EPIC_ITEM_IDS = {907104202, 907103324, 907104019, 905000065, 907104714}

