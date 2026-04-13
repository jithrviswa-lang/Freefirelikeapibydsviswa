from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import jwt
import os
import asyncio
from upstash_redis import Redis

app = Flask(__name__)

# -------------------------------------------------------------------
# Redis setup (persistent storage)
# -------------------------------------------------------------------
REDIS_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
if not REDIS_URL or not REDIS_TOKEN:
    raise Exception("Missing Redis environment variables")
redis = Redis(url=REDIS_URL, token=REDIS_TOKEN)

# Keys in Redis
TOKEN_APIS_KEY = "token_apis"
TOKEN_FILES_KEY = "token_files"  # JSON object: {region_group: [tokens]}
ACCOUNTS_KEY = "accounts"        # JSON array of accounts with region hint

# Default APIs (will be stored in Redis if not present)
DEFAULT_APIS = [
    "https://jwt-gen-api-v2.onrender.com/token",
    "http://d1.max-cloud.xyz:2009/token"
]

def init_redis():
    """Initialize Redis with default values if missing."""
    if not redis.exists(TOKEN_APIS_KEY):
        redis.set(TOKEN_APIS_KEY, json.dumps(DEFAULT_APIS))
    if not redis.exists(TOKEN_FILES_KEY):
        redis.set(TOKEN_FILES_KEY, json.dumps({"IND": [], "US": [], "BD": []}))
    if not redis.exists(ACCOUNTS_KEY):
        redis.set(ACCOUNTS_KEY, json.dumps([]))

init_redis()

# -------------------------------------------------------------------
# Region mapping (same as before)
# -------------------------------------------------------------------
REGION_IND = {"IND"}
REGION_US = {"BR", "US", "SAC", "NA"}

def get_region_group(region):
    r = region.upper()
    if r in REGION_IND: return "IND"
    if r in REGION_US: return "US"
    return "BD"

def get_token_filename(region):
    group = get_region_group(region)
    return group  # we use group as key in Redis

def get_credential_filename(region):
    group = get_region_group(region)
    return f"id_pass_{group.lower()}.json"  # not used for storage but kept for compatibility

def get_region_from_token(token):
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        region = payload.get("lock_region") or payload.get("noti_region")
        return region.upper() if region else "BD"
    except:
        return "BD"

def add_token_to_file(token, region):
    """Store token in Redis under the correct region group."""
    group = get_region_group(region)
    token_data = json.loads(redis.get(TOKEN_FILES_KEY))
    if token not in token_data[group]:
        token_data[group].append(token)
        redis.set(TOKEN_FILES_KEY, json.dumps(token_data))

def get_tokens_for_region(region):
    """Retrieve list of tokens for a given region."""
    group = get_region_group(region)
    token_data = json.loads(redis.get(TOKEN_FILES_KEY))
    return token_data.get(group, [])

def get_all_apis():
    return json.loads(redis.get(TOKEN_APIS_KEY))

def add_api(new_api):
    apis = get_all_apis()
    if new_api not in apis:
        apis.append(new_api)
        redis.set(TOKEN_APIS_KEY, json.dumps(apis))

def remove_api(index):
    apis = get_all_apis()
    if 0 <= index < len(apis):
        removed = apis.pop(index)
        redis.set(TOKEN_APIS_KEY, json.dumps(apis))
        return removed
    return None

def fetch_token_with_retry(uid, password, api_url, retries=3):
    url = f"{api_url}?uid={uid}&password={password}"
    for attempt in range(1, retries+1):
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("token")
                if token:
                    region = get_region_from_token(token)
                    return token, region
        except:
            pass
    return None, None

# -------------------------------------------------------------------
# Token refresh endpoint (call via cron every 6 hours)
# -------------------------------------------------------------------
@app.route('/refresh_tokens', methods=['GET'])
def refresh_tokens():
    """Delete all existing tokens and fetch fresh ones using all APIs."""
    # Clear existing tokens
    redis.set(TOKEN_FILES_KEY, json.dumps({"IND": [], "US": [], "BD": []}))
    # Get all accounts
    accounts = json.loads(redis.get(ACCOUNTS_KEY))
    apis = get_all_apis()
    success = 0
    for idx, acc in enumerate(accounts):
        uid = acc.get("uid")
        pwd = acc.get("password")
        if not uid or not pwd:
            continue
        start_idx = idx % len(apis)
        token = None
        region = None
        for i in range(len(apis)):
            api = apis[(start_idx + i) % len(apis)]
            token, region = fetch_token_with_retry(uid, pwd, api)
            if token:
                break
        if token and region:
            add_token_to_file(token, region)
            success += 1
    return jsonify({
        "status": "refresh completed",
        "total_accounts": len(accounts),
        "tokens_created": success
    })

# -------------------------------------------------------------------
# Account management endpoints
# -------------------------------------------------------------------
@app.route('/add_account/<uid>/<password>', methods=['GET'])
def add_account_simple(uid, password):
    return add_account_with_region(uid, password, "BD")

@app.route('/add_account/<uid>/<password>/<region>', methods=['GET'])
def add_account_with_region(uid, password, region):
    if not uid.isdigit():
        return jsonify({"error": "UID must be numeric"}), 400
    region_upper = region.upper()
    accounts = json.loads(redis.get(ACCOUNTS_KEY))
    for acc in accounts:
        if acc.get("uid") == uid:
            return jsonify({"error": f"UID {uid} already exists"}), 400
    accounts.append({"uid": uid, "password": password, "region": region_upper})
    redis.set(ACCOUNTS_KEY, json.dumps(accounts))
    return jsonify({
        "status": "success",
        "message": f"Account {uid} added (region {region_upper})",
        "total_accounts": len(accounts)
    })

# -------------------------------------------------------------------
# API management endpoints
# -------------------------------------------------------------------
@app.route('/add_api/<path:new_api>', methods=['GET'])
def add_api_endpoint(new_api):
    if not (new_api.startswith("http://") or new_api.startswith("https://")):
        return jsonify({"error": "Invalid URL"}), 400
    apis = get_all_apis()
    if new_api in apis:
        return jsonify({"error": "API already exists"}), 400
    add_api(new_api)
    return jsonify({"status": "success", "apis": get_all_apis()})

@app.route('/remove_api/<int:index>', methods=['GET'])
def remove_api_endpoint(index):
    removed = remove_api(index)
    if removed:
        return jsonify({"status": "success", "removed": removed, "apis": get_all_apis()})
    return jsonify({"error": "Invalid index"}), 400

@app.route('/list_apis', methods=['GET'])
def list_apis():
    return jsonify({"apis": get_all_apis()})

@app.route('/token_status', methods=['GET'])
def token_status():
    token_data = json.loads(redis.get(TOKEN_FILES_KEY))
    total_tokens = sum(len(v) for v in token_data.values())
    return jsonify({
        "apis": get_all_apis(),
        "tokens_per_region": token_data,
        "total_tokens": total_tokens
    })

# -------------------------------------------------------------------
# Like sending endpoint (async for Vercel)
# -------------------------------------------------------------------
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode()

def create_protobuf_message(user_id, region):
    msg = like_pb2.like()
    msg.uid = int(user_id)
    msg.region = region
    return msg.SerializeToString()

def create_protobuf(uid):
    msg = uid_generator_pb2.uid_generator()
    msg.saturn_ = int(uid)
    msg.garena = 1
    return msg.SerializeToString()

def enc(uid):
    return encrypt_message(create_protobuf(uid))

def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.11f1",
        'ReleaseVersion': "OB53"
    }
    resp = requests.post(url, data=edata, headers=headers, verify=False)
    binary = bytes.fromhex(resp.content.hex())
    info = like_count_pb2.Info()
    info.ParseFromString(binary)
    return info

async def send_likes(uid, server_name):
    protobuf = create_protobuf_message(uid, server_name)
    encrypted = encrypt_message(protobuf)
    tokens = get_tokens_for_region(server_name)
    if not tokens:
        return 0
    url = "https://client.ind.freefiremobile.com/LikeProfile" if server_name == "IND" else \
          "https://client.us.freefiremobile.com/LikeProfile" if server_name in {"BR","US","SAC","NA"} else \
          "https://clientbp.ggblueshark.com/LikeProfile"
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(min(100, len(tokens))):
            token = tokens[i]
            edata = bytes.fromhex(encrypted)
            headers = {
                'Authorization': f"Bearer {token}",
                'Content-Type': "application/x-www-form-urlencoded",
                'X-Unity-Version': "2018.4.11f1",
                'ReleaseVersion': "OB53"
            }
            tasks.append(session.post(url, data=edata, headers=headers))
        await asyncio.gather(*tasks)
    return len(tasks)

@app.route('/like', methods=['GET'])
async def handle_like():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "Missing uid or server_name"}), 400
    # Get player info for region validation
    try:
        resp = requests.get(f"https://nr-codex-info.vercel.app/get?uid={uid}", timeout=5)
        data = resp.json()
        api_region = data.get("AccountInfo", {}).get("AccountRegion", "NA")
    except:
        api_region = "NA"
    server_used = api_region if api_region != "NA" and server_name != api_region else server_name
    tokens = get_tokens_for_region(server_used)
    if not tokens:
        return jsonify({"error": "No tokens available for this region"}), 500
    token = tokens[0]
    encrypted_uid = enc(uid)
    before = make_request(encrypted_uid, server_used, token)
    before_like = int(MessageToJson(before).get('AccountInfo', {}).get('Likes', 0))
    await send_likes(uid, server_used)
    after = make_request(encrypted_uid, server_used, token)
    after_like = int(MessageToJson(after).get('AccountInfo', {}).get('Likes', 0))
    like_given = after_like - before_like
    result = {
        "Owner_of_the_api": "viswajeethu123",
        "RegionUsed": server_used,
        "LikesGivenByAPI": like_given,
        "LikesafterCommand": after_like,
        "LikesbeforeCommand": before_like,
        "PlayerNickname": MessageToJson(after).get('AccountInfo', {}).get('PlayerNickname', ''),
        "UID": int(MessageToJson(after).get('AccountInfo', {}).get('UID', 0)),
        "ReleaseVersion": "OB53",
        "status": 1 if like_given > 0 else 2
    }
    return jsonify(result)

# -------------------------------------------------------------------
# Vercel handler
# -------------------------------------------------------------------
app = app

if __name__ == '__main__':
    app.run(debug=True)