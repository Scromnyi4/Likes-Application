from flask import Flask, request, jsonify
import asyncio
import random
import time
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

app = Flask(__name__)

# ────────────────────────────────────────
#           TUNABLE SETTINGS
# ────────────────────────────────────────
MAX_CONCURRENT       = 12              # 8–15 is usually safest
BATCH_SIZE           = 30              # send 20–40 per batch
DELAY_BETWEEN_BATCH  = 2.2             # seconds (increase if banned often)
JITTER               = 0.9             # random ± this
MAX_ATTEMPTS         = 300             # realistic target — higher = more ban risk
REQUEST_TIMEOUT      = 10
# ────────────────────────────────────────

def load_tokens(server_name):
    server_name = server_name.upper()
    try:
        if server_name == "IND":
            fn = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            fn = "token_br.json"
        else:
            fn = "token_bd.json"
        with open(fn, "r") as f:
            data = json.load(f)
        # Expect list of dicts → extract tokens
        return [item["token"] for item in data if item.get("token")]
    except Exception as e:
        app.logger.error(f"Tokens load failed {server_name}: {e}")
        return []


def encrypt_message(plaintext: bytes) -> str | None:
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv  = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        enc = cipher.encrypt(padded)
        return binascii.hexlify(enc).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Encrypt failed: {e}")
        return None


def create_like_proto(uid: str, region: str) -> bytes | None:
    try:
        msg = like_pb2.like()
        msg.uid = int(uid)
        msg.region = region
        if hasattr(msg, 'ob_version'):
            msg.ob_version = "OB48"          # ← update if OB changed
        return msg.SerializeToString()
    except Exception:
        return None


def create_info_proto(uid: str) -> bytes | None:
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)
        msg.garena = 1
        if hasattr(msg, 'ob_version'):
            msg.ob_version = "OB48"
        return msg.SerializeToString()
    except Exception:
        return None


def get_like_url(server: str) -> str:
    s = server.upper()
    if s == "IND":              return "https://client.ind.freefiremobile.com/LikeProfile"
    if s in {"BR", "US", "SAC", "NA"}: return "https://client.us.freefiremobile.com/LikeProfile"
    return "https://clientbp.ggblueshark.com/LikeProfile"


def get_info_url(server: str) -> str:
    s = server.upper()
    if s == "IND":              return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    if s in {"BR", "US", "SAC", "NA"}: return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    return "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"


async def send_single_like(session: aiohttp.ClientSession, enc_data: str, token: str, url: str) -> bool:
    try:
        payload = bytes.fromhex(enc_data)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"          # ← may need update
        }
        async with session.post(url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT) as r:
            return r.status == 200
    except Exception:
        return False


async def send_batch(enc_like: str, tokens_batch: list[str], like_url: str, sem: asyncio.Semaphore) -> int:
    success = 0
    async with sem:
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT + 5)
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT + 3)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for tok in tokens_batch:
                tasks.append(send_single_like(session, enc_like, tok, like_url))
                await asyncio.sleep(random.uniform(0.05, 0.18))  # micro-delay

            results = await asyncio.gather(*tasks, return_exceptions=True)
            success = sum(1 for x in results if x is True)

    return success


async def send_multiple_likes(uid: str, server_name: str, like_url: str) -> int:
    tokens = load_tokens(server_name)
    if not tokens:
        return 0

    proto = create_like_proto(uid, server_name.upper())
    if not proto:
        return 0

    enc_like = encrypt_message(proto)
    if not enc_like:
        return 0

    total_success = 0
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    # Shuffle helps distribute load
    random.shuffle(tokens)

    for i in range(0, min(len(tokens), MAX_ATTEMPTS), BATCH_SIZE):
        batch = tokens[i:i + BATCH_SIZE]

        succ = await send_batch(enc_like, batch, like_url, semaphore)
        total_success += succ

        # Delay between batches — very important
        await asyncio.sleep(DELAY_BETWEEN_BATCH + random.uniform(-JITTER, JITTER))

        # Optional: stop early if almost nothing works anymore
        if succ <= 2 and i >= 90:
            break

    return total_success


def fetch_likes(encrypted: str, server: str, token: str):
    try:
        url = get_info_url(server)
        data = bytes.fromhex(encrypted)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
        r = requests.post(url, data=data, headers=headers, timeout=12, verify=False)
        if r.status_code != 200:
            return None

        msg = like_count_pb2.Info()
        msg.ParseFromString(r.content)
        # Adjust field path if protobuf definition changed
        return msg.AccountInfo.Likes if hasattr(msg, "AccountInfo") and hasattr(msg.AccountInfo, "Likes") else 0
    except Exception as e:
        app.logger.error(f"Fetch likes failed: {e}")
        return None


def enc_uid(uid):
    proto = create_info_proto(uid)
    if not proto: return None
    return encrypt_message(proto)


# ────────────────────────────────────────────────
#   The /like endpoint stays almost unchanged
#   (only like sending part replaced + minor safety)
# ────────────────────────────────────────────────
@app.route("/like", methods=["GET"])
def like_api():
    uid = request.args.get("uid")
    server = request.args.get("server_name", "").upper()

    if not uid or not server:
        return jsonify({"error": "uid & server_name required"}), 400

    try:
        tokens = load_tokens(server)
        if not tokens:
            return jsonify({"error": "Failed to load tokens"}), 500
        
        token = tokens[0]["token"] if isinstance(tokens[0], dict) else tokens[0]

        enc_uid_val = enc_uid(uid)
        if not enc_uid_val:
            return jsonify({"error": "Failed to encrypt UID"}), 500

        before = fetch_player_info(enc_uid_val, server, token)   # ← your original function
        if before is None:
            return jsonify({"error": "Failed to fetch player info before"}), 500

        before_json = json.loads(MessageToJson(before))
        before_like = int(before_json.get("AccountInfo", {}).get("Likes", 0))

        # like url
        if server == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server in {"BR", "US", "SAC", "NA"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        # ── Improved sending ────────────────────────────────
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            sent_ok = loop.run_until_complete(
                send_multiple_likes(uid, server, like_url)
            )
        finally:
            loop.close()

        # Give game server time to count likes
        time.sleep(3.0 + random.uniform(0, 2.0))

        after = fetch_player_info(enc_uid_val, server, token)
        if after is None:
            return jsonify({"error": "Failed to fetch player info after"}), 500

        after_json = json.loads(MessageToJson(after))
        acc = after_json.get("AccountInfo", {})

        after_like = int(acc.get("Likes", 0))
        likes_added = after_like - before_like

        result = {
            "UID": acc.get("UID", ""),
            "PlayerNickname": acc.get("PlayerNickname", ""),
            "PlayerLevel": acc.get("level", ""),
            "Region": acc.get("region", server),
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "LikesGivenByAPI": likes_added,
            "status": 1 if likes_added > 0 else 2
        }
        
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500


# your /check_tokens endpoint remains unchanged


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)
