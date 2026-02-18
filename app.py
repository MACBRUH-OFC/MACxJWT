from flask import Flask, request, jsonify
from flask_cors import CORS   # ← ADDED
import urllib3
import requests
import binascii
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import MajorLoginRes_pb2

app = Flask(__name__)

# ---------- ENABLE CORS (ADDED) ----------
CORS(app)   # allows all origins, methods, headers
# -----------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------- PROTO DECODE ----------------

def decode_protobuf(data):
    response = MajorLoginRes_pb2.MajorLoginRes()
    response.ParseFromString(data)
    return response


# ---------------- JWT DECODE ----------------

def decode_jwt_payload(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        payload = parts[1]

        # fix padding
        payload += "=" * (-len(payload) % 4)

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)

    except:
        return None


# ---------------- AES ENCRYPT ----------------

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)

    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain_text, AES.block_size))


# ---------------- GUEST TOKEN ----------------

def guest_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"

    headers = {
        "Host": "100067.connect.garena.com",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }

    response = requests.post(url, headers=headers, data=data)
    data = response.json()

    return data.get("access_token"), data.get("open_id")


# ---------------- MAJOR LOGIN ----------------

def MajorLogin(access_token, open_id, game_version):

    url = "https://loginbp.ggpolarbear.com/MajorLogin"

    data = bytes.fromhex(
        "1a13323032352d30342d31382032303a31343a3132220966726565206669726528013a08322e3130392e3135423a416e64726f6964204f532039202f204150492d32382028505133422e3139303830312e31323139313631312f47393635305a48553241524336294a0848616e6468656c64520b566f6461666f6e6520494e5a045749464960b60a68ee0572033238307a2141524d3634204650204153494d442041455320564d48207c2032383635207c20348001ea1e8a010f416472656e6f2028544d29203634309201104f70656e474c20455320332e312076319a012b476f6f676c657c39646465623966372d343930302d343661342d383961382d353330326535396336326431a2010f3130332e3138322e3130362e323533aa0102656eb201203137376137396635616462353732323836386533313765653164373963333661ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d583931304eea014036363332386231313137383330313566313132643163633966326165366538306435653231666130316234326530303566386235656330653835376465666437f00101ca020b566f6461666f6e6520494ed2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003c9c302e803d59502f003d713f803be058004b5d20188048ff201900496a4029804c9c302c80402d204402f646174612f6170702f636f6d2e6474732e66726565666972656d61782d505134696367307542345544706f696d366b71472d513d3d2f6c69622f61726d3634e00402ea046066376464366430613263356535616435316139333630306662633035333863377c2f646174612f6170702f636f6d2e6474732e66726565666972656d61782d505134696367307542345544706f696d366b71472d513d3d2f626173652e61706bf00402f804028a050236349a050a32303139313134393336b205094f70656e474c455333b805ff7fc00504ca0500e005ec42ea050b616e64726f69645f6d6178f2055c4b717348542f5831335a346e486f496c566553715579443677674132374869794c78424d2b534253426b543263623866624a4d6b706d6b576e38443261334970586957536e2f2f443145477052797277786f7131772b6a705741773df805fbe4068806019006019a060134a2060134"
    )

    data = data.replace(
        "177a79f5adb5722868e317ee1d79c36a".encode(),
        open_id.encode()
    )

    data = data.replace(
        "66328b111783015f112d1cc9f2ae6e80d5e21fa01b42e005f8b5ec0e857defd7".encode(),
        access_token.encode()
    )

    payload = encrypt_api(data.hex())

    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": game_version
    }

    response = requests.post(url, headers=headers, data=payload, verify=False)

    if response.status_code == 200:
        return response.content

    return None


# ---------------- API ROUTE ----------------

@app.route("/get_jwt_token")
def get_jwt_token():

    uid = request.args.get("uid")
    password = request.args.get("password")
    version = request.args.get("version")

    if not uid or not password:
        return jsonify({"error": "UID and password are required"}), 400

    if not version:
        return jsonify({"error": "Game version required (example: &version=OB52)"}), 400

    access_token, open_id = guest_token(uid, password)

    if not access_token:
        return jsonify({"error": "Invalid UID or Password"}), 401

    response = MajorLogin(access_token, open_id, version)

    if not response:
        return jsonify({"error": "Login Failed"}), 500

    decoded_response = decode_protobuf(response)
    token = decoded_response.token

    jwt_payload = decode_jwt_payload(token)

    account_info = None
    if jwt_payload:
        account_info = {
            "account_id": jwt_payload.get("account_id"),
            "nickname": jwt_payload.get("nickname"),
            "platform": jwt_payload.get("plat_id"),
            "region": jwt_payload.get("lock_region") or jwt_payload.get("noti_region")
        }

    return jsonify({
        "status": "success",
        "account_info": account_info,
        "token": token
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)