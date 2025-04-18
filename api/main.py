from http.server import BaseHTTPRequestHandler
from io import BytesIO
import json
import asyncio
import aiohttp
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import my_pb2

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

url = "https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow"
headers = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/octet-stream",
    'Expect': "100-continue",
    'Authorization': "Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMTM4MjYxNTc4OCwibmlja25hbWUiOiJTY3JvbW55aXwyIiwibm90aV9yZWdpb24iOiJSVSIsImxvY2tfcmVnaW9uIjoiUlUiLCJleHRlcm5hbF9pZCI6IjFjMTU2NTVhYTUyMmQzODdkZDNlY2M0YmRiNjlmODc2IiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MSwiY2xpZW50X3ZlcnNpb24iOiIxLjEwOC4zIiwiZW11bGF0b3Jfc2NvcmUiOjEwMCwiaXNfZW11bGF0b3IiOnRydWUsImNvdW50cnlfY29kZSI6IlVTIiwiZXh0ZXJuYWxfdWlkIjozODA0Njc4Mzc2LCJyZWdfYXZhdGFyIjoxMDIwMDAwMDcsInNvdXJjZSI6NCwibG9ja19yZWdpb25fdGltZSI6MTc0MTYxNTUwOCwiY2xpZW50X3R5cGUiOjIsInNpZ25hdHVyZV9tZDUiOiIiLCJ1c2luZ192ZXJzaW9uIjoxLCJyZWxlYXNlX2NoYW5uZWwiOiIzcmRfcGFydHkiLCJyZWxlYXNlX3ZlcnNpb24iOiJPQjQ4IiwiZXhwIjoxNzQzMDE5ODM4fQ.8Duw10jzx8Uqywdy1Pjy_6b0wvYA0Ilt6B9qEls27-I",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB46"
}

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/send_visits'):
            self.handle_send_visits()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def handle_send_visits(self):
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        user_id = params.get('user_id', [None])[0]
        if not user_id:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "user_id parameter is required"}).encode())
            return

        try:
            user_id = int(user_id)
            success_count = asyncio.run(self.send_visits(user_id, 1000))
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                "message": f"Sent {success_count} visits to user {user_id}",
                "success_count": success_count,
                "user_id": user_id
            }
            self.wfile.write(json.dumps(response).encode())
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def create_data_message(self, field1_value, field2_value):
        data = my_pb2.Data()
        data.field1 = field1_value
        data.field2 = field2_value
        return data

    def serialize_data_message(self, data_message):
        return data_message.SerializeToString()

    def encrypt_message(self, key, iv, plaintext):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        return cipher.encrypt(padded_message)

    async def send_request(self, session, request_number, edata):
        try:
            async with session.post(url, data=edata, headers=headers, ssl=False) as response:
                print(f"Request {request_number}, status: {response.status}")
                return True
        except Exception as e:
            print(f"Error in request {request_number}: {e}")
            return False

    async def send_visits(self, user_id, count):
        data_message = self.create_data_message(user_id, 7)
        serialized_message = self.serialize_data_message(data_message)
        encrypted_data = self.encrypt_message(AES_KEY, AES_IV, serialized_message)
        edata_bytes = encrypted_data
        
        success_count = 0
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for i in range(1, count + 1):
                tasks.append(self.send_request(session, i, edata_bytes))
                
                if i % 100 == 0:
                    results = await asyncio.gather(*tasks)
                    success_count += sum(results)
                    tasks = []
            
            if tasks:
                results = await asyncio.gather(*tasks)
                success_count += sum(results)
        
        return success_count
