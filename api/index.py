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
import random
import logging
from aiohttp import TCPConnector

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
HEADERS = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB49"
}
API_KEY = "sk_5a6bF3r9PxY2qLmZ8cN1vW7eD0gH4jK"
CONCURRENT_REQUESTS = 100  # Number of concurrent requests for likes

def load_tokens(server_name):
    try:
        token_file = {
            "IND": "token_ind.json",
            "BR": "token_br.json",
            "US": "token_br.json",
            "SAC": "token_br.json",
            "NA": "token_br.json"
        }.get(server_name, "token_bd.json")
        
        with open(token_file, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(session, encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = HEADERS.copy()
        headers['Authorization'] = f"Bearer {token}"
        
        async with session.post(url, data=edata, headers=headers) as response:
            if response.status != 200:
                logger.error(f"Request failed with status code: {response.status}")
                return None
            return await response.text()
    except Exception as e:
        logger.error(f"Exception in send_request: {e}")
        return None

async def send_concurrent_requests(uid, server_name, url, tokens):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if not protobuf_message:
            logger.error("Failed to create protobuf message.")
            return False
        
        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid:
            logger.error("Encryption failed.")
            return False
        
        # Create a single session for all requests
        connector = TCPConnector(limit=CONCURRENT_REQUESTS, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for token_data in tokens[:CONCURRENT_REQUESTS]:
                token = token_data["token"]
                task = asyncio.create_task(send_request(session, encrypted_uid, token, url))
                tasks.append(task)
            
            await asyncio.gather(*tasks)
        return True
    except Exception as e:
        logger.error(f"Exception in send_concurrent_requests: {e}")
        return False

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        logger.error(f"Error creating uid protobuf: {e}")
        return None

def get_encrypted_uid(uid):
    protobuf_data = create_protobuf(uid)
    if not protobuf_data:
        return None
    return encrypt_message(protobuf_data)

def get_server_url(server_name, endpoint):
    if server_name == "IND":
        return f"https://client.ind.freefiremobile.com/{endpoint}"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return f"https://client.us.freefiremobile.com/{endpoint}"
    else:
        return f"https://clientbp.ggblueshark.com/{endpoint}"

async def make_async_request(encrypt, server_name, token):
    try:
        url = get_server_url(server_name, "GetPlayerPersonalShow")
        edata = bytes.fromhex(encrypt)
        headers = HEADERS.copy()
        headers['Authorization'] = f"Bearer {token}"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    logger.error(f"Request failed with status: {response.status}")
                    return None
                hex_data = (await response.read()).hex()
                binary = bytes.fromhex(hex_data)
                return decode_protobuf(binary)
    except Exception as e:
        logger.error(f"Error in make_async_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

async def get_player_info(encrypted_uid, server_name, token):
    result = await make_async_request(encrypted_uid, server_name, token)
    if not result:
        return None
    
    try:
        jsone = MessageToJson(result)
        data = json.loads(jsone)
        return {
            'likes': int(data.get('AccountInfo', {}).get('Likes', 0)),
            'uid': int(data.get('AccountInfo', {}).get('UID', 0)),
            'name': str(data.get('AccountInfo', {}).get('PlayerNickname', ''))
        }
    except Exception as e:
        logger.error(f"Error processing player info: {e}")
        return None

@app.route('/like', methods=['GET'])
async def handle_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    key = request.args.get("key", "")

    if key != API_KEY:
        return jsonify({"error": "Unauthorized. Invalid key.", "status": 0}), 403

    if not uid or not region:
        return jsonify({"error": "UID and region are required", "status": 0}), 400

    try:
        # Load tokens once
        tokens = load_tokens(region)
        if not tokens or len(tokens) < CONCURRENT_REQUESTS:
            return jsonify({
                "error": f"Not enough tokens available (need {CONCURRENT_REQUESTS})",
                "status": 0
            }), 400

        # Get initial player info
        encrypted_uid = get_encrypted_uid(uid)
        if not encrypted_uid:
            return jsonify({"error": "Encryption failed", "status": 0}), 500

        token = tokens[0]['token']
        before_info = await get_player_info(encrypted_uid, region, token)
        if not before_info:
            return jsonify({"error": "Failed to get initial player info", "status": 0}), 500

        # Send like requests
        like_url = get_server_url(region, "LikeProfile")
        success = await send_concurrent_requests(uid, region, like_url, tokens)
        if not success:
            return jsonify({"error": "Failed to send like requests", "status": 0}), 500

        # Get updated player info
        after_info = await get_player_info(encrypted_uid, region, token)
        if not after_info:
            return jsonify({"error": "Failed to get updated player info", "status": 0}), 500

        like_given = after_info['likes'] - before_info['likes']
        status = 1 if like_given > 0 else 2

        result = {
            "LikesGivenByAPI": like_given,
            "LikesAfterCommand": after_info['likes'],
            "LikesBeforeCommand": before_info['likes'],
            "PlayerNickname": after_info['name'],
            "UID": after_info['uid'],
            "status": status
        }
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return jsonify({
            "error": str(e),
            "status": 0
        }), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
