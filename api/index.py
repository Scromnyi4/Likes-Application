from flask import Flask, request, jsonify
import asyncio
import aiohttp
import requests
import json
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import like_pb2
import like_count_pb2
import uid_generator_pb2

app = Flask(__name__)

# Конфигурация
TOKENS_FILES = {
    "IND": "token_ind.json",
    "BR": "token_br.json",
    "US": "token_br.json",
    "SAC": "token_br.json",
    "NA": "token_br.json"
}
DEFAULT_TOKEN_FILE = "token_bd.json"

URLS = {
    "IND": {
        "like": "https://client.ind.freefiremobile.com/LikeProfile",
        "player": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    },
    "BR": {
        "like": "https://client.us.freefiremobile.com/LikeProfile",
        "player": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    },
    "US": {
        "like": "https://client.us.freefiremobile.com/LikeProfile",
        "player": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    },
    "SAC": {
        "like": "https://client.us.freefiremobile.com/LikeProfile",
        "player": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    },
    "NA": {
        "like": "https://client.us.freefiremobile.com/LikeProfile",
        "player": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    }
}
DEFAULT_URL = {
    "like": "https://clientbp.ggblueshark.com/LikeProfile",
    "player": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
}

# Утилитардык функциялар
def load_tokens(server_name):
    try:
        file_path = TOKENS_FILES.get(server_name, DEFAULT_TOKEN_FILE)
        with open(file_path, "r") as f:
            return json.load(f)
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

def create_uid_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
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

# Асинхрондук функциялар
async def send_request(encrypted_uid, token, url):
    try:
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
            async with session.post(url, data=bytes.fromhex(encrypted_uid), headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if not protobuf_message:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid:
            return None
        tokens = load_tokens(server_name)
        if not tokens:
            return None
        
        tasks = []
        random_indices = random.sample(range(len(tokens)), min(101, len(tokens)))
        for index in random_indices:
            token = tokens[index]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

# Синхрондук функциялар
def get_player_info(encrypt, server_name, token):
    try:
        url = URLS.get(server_name, DEFAULT_URL)["player"]
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
        response = requests.post(url, data=bytes.fromhex(encrypt), headers=headers, verify=False)
        return decode_protobuf(bytes.fromhex(response.content.hex()))
    except Exception as e:
        app.logger.error(f"Error in get_player_info: {e}")
        return None

# Маршрут
@app.route('/like', methods=['GET'])
def handle_like():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        tokens = load_tokens(server_name)
        if not tokens:
            return jsonify({"error": "Failed to load tokens"}), 500
            
        token = tokens[0]['token']
        encrypted_uid = encrypt_message(create_uid_protobuf(uid))
        if not encrypted_uid:
            return jsonify({"error": "Encryption failed"}), 500

        # Before likes
        before = get_player_info(encrypted_uid, server_name, token)
        if not before:
            return jsonify({"error": "Failed to retrieve initial player info"}), 500
            
        data_before = json.loads(MessageToJson(before))
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))

        # Send like requests
        like_url = URLS.get(server_name, DEFAULT_URL)["like"]
        asyncio.run(send_multiple_requests(uid, server_name, like_url))

        # After likes
        after = get_player_info(encrypted_uid, server_name, token)
        if not after:
            return jsonify({"error": "Failed to retrieve player info after likes"}), 500
            
        data_after = json.loads(MessageToJson(after))
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
        player_name = data_after.get('AccountInfo', {}).get('PlayerNickname', '')

        like_given = after_like - before_like
        if like_given == 0:
            return "Player has reached max likes."
            
        result = {
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_uid,
            "status": 1
        }
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
