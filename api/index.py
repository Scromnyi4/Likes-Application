import requests
from functools import wraps
from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import json
from api import like_pb2
from api import like_count_pb2
from api import uid_generator_pb2
from google.protobuf.message import DecodeError
import random
from datetime import datetime, timedelta
import threading
import time
import os

app = Flask(__name__)

# API_KEYS структурасы
API_KEYS = {
    "Scromnyi225": {"status": "active", "created_at": "2025-04-18", "duration_days": 30},
    "HELLO-WORLD": {"status": "inactive", "created_at": "2025-04-18", "duration_days": 30}
}

# API ачкычын текшерүү декоратору
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is missing."}), 401
        if api_key not in API_KEYS:
            return jsonify({"error": "Invalid API key."}), 401
        if API_KEYS[api_key]["status"] != "active":
            return jsonify({"error": "API key is inactive."}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET'])
def info():
    info_text = """

    Scromnyi _</>

    Contact Information: 

    - Telegram - @scromnyimodz444
    - Telegram Group - @FreeFireInfo444
    
    - Join For Free Fire leaks - https://t.me/ffleaks_scromnyi444

    Taala1bek    |    2025

    """
    return jsonify({"||| WLX.ScorpionX |||": info_text.strip().split('\n')})

@app.route('/Checkban', methods=['GET'])
@require_api_key
def check_banned():
    try:
        player_id = request.args.get('id')
        if not player_id:
            return jsonify({"error": "Player ID is required"}), 400

        url = f"https://ff.garena.com/api/antihack/check_banned?lang=en&uid={player_id}"
        headers = {
            'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            'Accept': "application/json, text/plain, */*",
            'authority': "ff.garena.com",
            'accept-language': "en-GB,en-US;q=0.9,en;q=0.8",
            'referer': "https://ff.garena.com/en/support/",
            'sec-ch-ua': "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"",
            'sec-ch-ua-mobile': "?1",
            'sec-ch-ua-platform': "\"Android\"",
            'sec-fetch-dest': "empty",
            'sec-fetch-mode': "cors",
            'sec-fetch-site': "same-origin",
            'x-requested-with': "B6FksShzIgjfrYImLpTsadjS86sddhFH",
            'Cookie': "_ga_8RFDT0P8N9=GS1.1.1706295767.2.0.1706295767.0.0.0; apple_state_key=8236785ac31b11ee960a621594e13693; datadome=bbC6XTzUAS0pXgvEs7u",
        }

        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            is_banned = result.get('data', {}).get('is_banned', 0)
            period = result.get('data', {}).get('period', 0)

            return jsonify({
                "player_id": player_id,
                "is_banned": bool(is_banned),
                "ban_period": period if is_banned else 0,
                "status": "BANNED" if is_banned else "NOT BANNED"
            })
        else:
            return jsonify({"error": "Failed to fetch data from server"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/check_key', methods=['GET'])
def check_key():
    api_key = request.args.get('key')
    if not api_key:
        return jsonify({"error": "API key is missing"}), 401
    if api_key in API_KEYS:
        return jsonify({
            "status": "valid",
            "key_status": API_KEYS[api_key]["status"]
        })
    return jsonify({"status": "invalid"}), 401

### LIKE PART ###

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        random_indices = random.sample(range(len(tokens)), 100)  # 100 лайк
        for index in random_indices:
            token = tokens[index]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

@app.route('/likes', methods=['GET'])
@require_api_key
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("region", "").upper()
    if not uid:
        return jsonify({"error": "UID & Key Required."}), 400

    try:
        def process_request():
            tokens = load_tokens(server_name)
            if tokens is None:
                raise Exception("Failed to load tokens.")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # Лайктар алдындагы маалымат
            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            # Серверге жараша лайк URL
            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            # Асинхрондуу сурамдарды жөнөтүү
            asyncio.run(send_multiple_requests(uid, server_name, url))

            # Лайктардан кийинки маалымат
            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like

            # Эгер лайктар 0 болсо
            if like_given == 0:
                return {
                    "Message": "Player has reached max likes today.",
                    "Status": False
                }

            status = 1 if like_given != 0 else 2
            result = {
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

# Жаңы /key эндпойнту
@app.route('/key', methods=['POST'])
@require_api_key
def add_key():
    try:
        key_name = request.args.get('keyname')
        days = request.args.get('days')
        
        if not key_name or not days:
            return jsonify({"error": "Key name and days are required."}), 400
        
        try:
            days = int(days)
            if days <= 0:
                raise ValueError("Days must be a positive integer.")
        except ValueError:
            return jsonify({"error": "Invalid days format. Must be a positive integer."}), 400

        created_at = datetime.now().strftime("%Y-%m-%d")
        API_KEYS[key_name] = {
            "status": "active",
            "created_at": created_at,
            "duration_days": days
        }

        created_date = datetime.strptime(created_at, "%Y-%m-%d")
        expiry_date = created_date + timedelta(days=days)
        remaining_days = (expiry_date - datetime.now()).days

        return jsonify({
            "key_name": key_name,
            "status": "active",
            "created_at": created_at,
            "duration_days": days,
            "remaining_days": max(0, remaining_days)
        }), 201
    except Exception as e:
        app.logger.error(f"Error adding key: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
