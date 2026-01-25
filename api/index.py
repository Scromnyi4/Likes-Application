from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.json_format import MessageToJson, Parse
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import time

app = Flask(__name__)

# Сервер атын алдын ала коюу
DEFAULT_SERVER_NAME = "BD"

# Токендерди жүктөө функциясы
def load_tokens(server_name):
    try:
        # Бардык учурда BD токендерин колдон
        with open("token_bd.json", "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens: {e}")
        return None

# Шифрлоо функциясы
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

# Дешифрлоо функциясы
def decrypt_message(encrypted_hex):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = binascii.unhexlify(encrypted_hex)
        decrypted_message = cipher.decrypt(encrypted_message)
        return unpad(decrypted_message, AES.block_size)
    except Exception as e:
        app.logger.error(f"Error decrypting message: {e}")
        return None

# Like протобуфту түзүү
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

# UID генератор протобуфу
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

# UID шифрлоо
def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

# Протобуфту декоддоо
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

# Like сурамдарын жөнөтүү
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
                    return False
                return True
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return False

# Көп сандагы сурамдарды жөнөтүү
async def send_multiple_requests(uid, server_name, url, count):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return {"successful": 0, "failed": count}
        
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return {"successful": 0, "failed": count}
        
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return {"successful": 0, "failed": count}
        
        tasks = []
        successful = 0
        failed = 0
        
        for i in range(count):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result is True:
                successful += 1
            else:
                failed += 1
        
        return {"successful": successful, "failed": failed}
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return {"successful": 0, "failed": count}

# Базалык сурам жөнөтүү
def make_request(encrypt, server_name, token):
    try:
        # BD сервери үчүн URL
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
            'ReleaseVersion': "OB52"
        }
        
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        if response.status_code != 200:
            app.logger.error(f"Request failed with status code: {response.status_code} and response: {response.text}")
            return None
        
        binary = response.content
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

# Учурдагы упайларды алуу
def get_current_likes(uid, server_name, token):
    try:
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return None
        
        result = make_request(encrypted_uid, server_name, token)
        if result is None:
            return None
        
        json_data = MessageToJson(result)
        data = json.loads(json_data)
        
        account_info = data.get('AccountInfo', {})
        likes = account_info.get('Likes', 0)
        level = account_info.get('level', 0)
        player_name = account_info.get('PlayerNickname', '')
        player_uid = account_info.get('UID', 0)
        region = account_info.get('region', server_name)
        
        return {
            'likes': int(likes) if likes else 0,
            'level': int(level) if level else 0,
            'name': str(player_name),
            'uid': str(player_uid),
            'region': str(region)
        }
    except Exception as e:
        app.logger.error(f"Error getting current likes: {e}")
        return None

# Негизги API endpoint
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    count_param = request.args.get("count", "")
    
    if not uid:
        return jsonify({"error": "UID is required"}), 400
    
    # Сервер атын алдын ала коюу
    server_name = DEFAULT_SERVER_NAME
    
    # Like санын аныктоо
    available_likes = [50, 100, 150, 220]
    like_count = 0
    
    if count_param:
        try:
            like_count = int(count_param)
            # Максималдуу чектөө
            if like_count > 220:
                like_count = 220
            elif like_count < 1:
                like_count = 50  # Минималдуу маани
        except ValueError:
            # Эгерде текст болсо
            if "50" in count_param:
                like_count = 50
            elif "100" in count_param:
                like_count = 100
            elif "150" in count_param:
                like_count = 150
            elif "220" in count_param:
                like_count = 220
            else:
                # Жок болсо, стандарттык маани
                like_count = 100
    else:
        # Параметр жок болсо, стандарттык маани
        like_count = 100
    
    try:
        # Токендерди жүктөө
        tokens = load_tokens(server_name)
        if tokens is None or len(tokens) == 0:
            return jsonify({"error": "No tokens available"}), 500
        
        token = tokens[0]['token']
        
        # Like сурамдарды жөнөтүүдөн мурун маалымат алуу
        before_data = get_current_likes(uid, server_name, token)
        if before_data is None:
            return jsonify({"error": "Failed to get player information"}), 500
        
        app.logger.info(f"Likes before command: {before_data['likes']}")
        
        # Like сурамдарды жөнөтүү
        url = "https://clientbp.ggblueshark.com/LikeProfile"
        
        # Like сурамдарды жөнөтүү
        result = asyncio.run(send_multiple_requests(uid, server_name, url, like_count))
        
        # Кичинекей күтүү (сервер маалыматты жаңыртышы үчүн)
        time.sleep(2)
        
        # Like сурамдарды жөнөтүүдөн кийин маалымат алуу
        after_data = get_current_likes(uid, server_name, token)
        if after_data is None:
            # Эгерде кийинки маалымат алуу ишке ашпаса, мурунку маалыматты колдон
            after_data = before_data.copy()
        
        # Жоопту түзүү
        likes_added = after_data['likes'] - before_data['likes']
        
        # Эгерде кошулган like терс болсо, нөлгө коюу
        if likes_added < 0:
            likes_added = 0
        
        response_data = {
            "failed_likes": result.get("failed", 0),
            "player_level": before_data['level'],
            "likes_added": likes_added,
            "likes_after": after_data['likes'],
            "likes_before": before_data['likes'],
            "name": before_data['name'],
            "region": before_data['region'],
            "uid": before_data['uid']
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

# Сабактоочу endpoint
@app.route('/')
def index():
    return """
    <h1>FreeFire Like API</h1>
    <p>API endpoint: /like</p>
    <p>Parameters:</p>
    <ul>
        <li>uid - Player UID (required)</li>
        <li>count - Number of likes to send (optional, default: 100)</li>
    </ul>
    <p>Example URLs:</p>
    <ul>
        <li><a href="/like?uid=14419778896">/like?uid=14419778896</a></li>
        <li><a href="/like?uid=14419778896&count=50">/like?uid=14419778896&count=50</a></li>
        <li><a href="/like?uid=14419778896&count=100">/like?uid=14419778896&count=100</a></li>
        <li><a href="/like?uid=14419778896&count=150">/like?uid=14419778896&count=150</a></li>
        <li><a href="/like?uid=14419778896&count=220">/like?uid=14419778896&count=220</a></li>
    </ul>
    <p><strong>Note:</strong> Server is automatically set to BD/SG region</p>
    """

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
