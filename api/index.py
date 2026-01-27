
from flask import Flask, request, jsonify
import asyncio
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
        if hasattr(message, 'ob_version'):
            message.ob_version = "OB48"
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        if hasattr(message, 'ob_version'):
            message.ob_version = "OB48"
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc_uid(uid):
    """Encrypt UID for player info fetching"""
    try:
        protobuf_data = create_protobuf(uid)
        if protobuf_data is None:
            return None
        encrypted_uid = encrypt_message(protobuf_data)
        return encrypted_uid
    except Exception as e:
        app.logger.error(f"Error in enc_uid: {e}")
        return None

def fetch_player_info(encrypted_uid, server_name, token):
    """Fetch player information"""
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        
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
            'ReleaseVersion': "OB52"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code != 200:
            app.logger.error(f"Request failed with status code: {response.status_code} and response: {response.text}")
            return None
        binary = response.content
        decode = decode_protobuf(binary)
        return decode
    except Exception as e:
        app.logger.error(f"Error in fetch_player_info: {e}")
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
            'ReleaseVersion': "OB52"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    text = await response.text()
                    app.logger.error(f"Request failed with status code: {response.status} and response: {text}")
                    return None
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_likes(uid, server_name, url):
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
        for i in range(500):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_likes: {e}")
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
        
        token = tokens[0]["token"]

        # Get likes before command
        encrypted_uid = enc_uid(uid)
        if not encrypted_uid:
            return jsonify({"error": "Failed to encrypt UID"}), 500
            
        before = fetch_player_info(encrypted_uid, server, token)
        if before is None:
            return jsonify({"error": "Failed to fetch player info before"}), 500

        before_json = json.loads(MessageToJson(before))
        before_like = int(before_json["AccountInfo"].get("Likes", 0))

        # Determine like URL
        if server == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server in {"BR", "US", "SAC", "NA"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send multiple likes
        asyncio.run(send_multiple_likes(uid, server, like_url))

        # Get likes after command
        after = fetch_player_info(encrypted_uid, server, token)
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

# Токендерди текшерүү үчүн кошумча endpoint
@app.route("/check_tokens/<server_name>", methods=["GET"])
def check_tokens(server_name):
    server_name = server_name.upper()
    tokens = load_tokens(server_name)
    
    if not tokens:
        return jsonify({"error": "Токендер жүктөлгөн жок"}), 400
    
    # Ар бир токенди текшерүү
    valid_tokens = []
    invalid_tokens = []
    
    for token_info in tokens:
        token = token_info.get("token", "")
        # JWT туура форматында болушу керек (3 бөлүктөн)
        if token.count('.') == 2:
            valid_tokens.append(token[:20] + "...")
        else:
            invalid_tokens.append(token[:30] + "..." if len(token) > 30 else token)
    
    result = {
        "server": server_name,
        "total_tokens": len(tokens),
        "valid_tokens_count": len(valid_tokens),
        "invalid_tokens_count": len(invalid_tokens),
        "valid_tokens_sample": valid_tokens[:3] if valid_tokens else [],
        "invalid_tokens_sample": invalid_tokens[:3] if invalid_tokens else []
    }
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)
