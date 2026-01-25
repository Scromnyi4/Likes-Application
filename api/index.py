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
    """Load tokens from JSON file based on server name"""
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
    """Encrypt message using AES-CBC"""
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

def create_like_protobuf(user_id, region):
    """Create protobuf message for like request"""
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        if hasattr(message, 'ob_version'):
            message.ob_version = "OB52"
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating like protobuf message: {e}")
        return None

def create_uid_protobuf(uid):
    """Create protobuf message for UID encryption"""
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

def encrypt_uid(uid):
    """Encrypt UID for player info requests"""
    protobuf_data = create_uid_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

async def send_like_request(encrypted_uid, token, url):
    """Send a single like request asynchronously"""
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
                    app.logger.error(f"Request failed with status {response.status}: {text}")
                    return None
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_like_request: {e}")
        return None

async def send_multiple_likes(uid, server_name, url, count=100):
    """Send multiple like requests asynchronously with specified count"""
    try:
        region = server_name
        protobuf_message = create_like_protobuf(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None, 0
            
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None, 0
            
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None, 0
            
        # Use specified count or max available tokens
        actual_count = min(count, len(tokens))
        
        tasks = []
        for i in range(actual_count):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_like_request(encrypted_uid, token, url))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results, actual_count
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_likes: {e}")
        return None, 0

def fetch_player_info(encrypted_uid, server_name, token):
    """Fetch player information from server"""
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
            app.logger.error(f"Request failed with status {response.status_code}: {response.text}")
            return None
            
        return decode_protobuf(response.content)
    except Exception as e:
        app.logger.error(f"Error in fetch_player_info: {e}")
        return None

def decode_protobuf(binary):
    """Decode protobuf response"""
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

@app.route('/like', methods=['GET'])
def like_api():
    """
    Main like endpoint with optional count parameter.
    Usage: /like?uid=123456&server_name=IND&count=50
    Default count: 100 if not specified
    """
    uid = request.args.get("uid")
    server = request.args.get("server_name", "").upper()
    count = request.args.get("count", default=100, type=int)

    if not uid or not server:
        return jsonify({"error": "uid and server_name parameters are required"}), 400

    if count <= 0:
        return jsonify({"error": "count must be a positive number"}), 400

    try:
        # Load tokens for the specified server
        tokens = load_tokens(server)
        if not tokens:
            return jsonify({"error": f"No tokens available for server {server}"}), 500
            
        if count > len(tokens):
            app.logger.warning(f"Requested {count} likes but only {len(tokens)} tokens available")

        # Get first token for player info requests
        token = tokens[0]["token"]

        # Encrypt UID for player info requests
        encrypted_uid = encrypt_uid(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Failed to encrypt UID"}), 500

        # Get initial player info
        before = fetch_player_info(encrypted_uid, server, token)
        if before is None:
            return jsonify({"error": "Failed to fetch initial player information"}), 500

        # Parse initial likes count
        before_json = json.loads(MessageToJson(before))
        account_info_before = before_json.get("AccountInfo", {})
        before_like = int(account_info_before.get("Likes", 0))
        
        app.logger.info(f"Likes before sending: {before_like}")

        # Determine like URL based on server
        if server == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server in {"BR", "US", "SAC", "NA"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send specified number of likes
        app.logger.info(f"Sending {count} likes to UID {uid} on server {server}")
        results, actual_count = asyncio.run(send_multiple_likes(uid, server, like_url, count))
        
        if results is None:
            return jsonify({"error": "Failed to send likes"}), 500

        # Count successful responses
        successful_requests = sum(1 for result in results if result is not None and not isinstance(result, Exception))
        app.logger.info(f"Successfully sent {successful_requests} out of {actual_count} requests")

        # Get updated player info
        after = fetch_player_info(encrypted_uid, server, token)
        if after is None:
            return jsonify({"error": "Failed to fetch updated player information"}), 500
            
        # Parse updated player info
        after_json = json.loads(MessageToJson(after))
        account_info_after = after_json.get("AccountInfo", {})

        # Calculate likes added
        after_like = int(account_info_after.get("Likes", 0))
        likes_added = after_like - before_like

        # Prepare response
        result = {
            "UID": account_info_after.get("UID", uid),
            "PlayerNickname": account_info_after.get("PlayerNickname", "Unknown"),
            "PlayerLevel": account_info_after.get("Level", "Unknown"),
            "Region": account_info_after.get("region", server),
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "LikesGivenByAPI": likes_added,
            "TokensUsed": actual_count,
            "RequestedCount": count,
            "SuccessfulRequests": successful_requests,
            "status": 1 if likes_added > 0 else 2
        }
        
        return jsonify(result)

    except ValueError as e:
        app.logger.error(f"Value error: {e}")
        return jsonify({"error": f"Invalid parameter value: {str(e)}"}), 400
    except Exception as e:
        app.logger.error(f"Unexpected error in like_api: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, port=5000)
