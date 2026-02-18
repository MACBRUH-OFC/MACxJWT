from flask import Flask, request, jsonify
import requests
import base64
import json
import urllib3
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ----------------------------------------
# AES Encryption
# ----------------------------------------
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)

    key = bytes([
        89, 103, 38, 116, 99, 37, 68, 69,
        117, 104, 54, 37, 90, 99, 94, 56
    ])

    iv = bytes([
        54, 111, 121, 90, 68, 114, 50, 50,
        69, 51, 121, 99, 104, 106, 77, 37
    ])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))

    return cipher_text


# ----------------------------------------
# Decode JWT payload
# ----------------------------------------
def decode_jwt(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except:
        return None


# ----------------------------------------
# STEP 1 — Guest Token Login
# ----------------------------------------
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

    if response.status_code != 200:
        return None, None

    result = response.json()

    return result.get("access_token"), result.get("open_id")


# ----------------------------------------
# STEP 2 — MajorLogin (Generate JWT)
# ----------------------------------------
def MajorLogin(access_token, open_id, version):

    url = "https://loginbp.ggpolarbear.com/MajorLogin"

    # original hex payload
    data = bytes.fromhex(
        "1a13323032352d30342d31382032303a31343a3132220966726565206669726528013a08322e3130392e3135423a416e64726f6964204f532039202f204150492d32382028505133422e3139303830312e31323139313631312f47393635305a48553241524336294a0848616e6468656c64520b566f6461666f6e6520494e5a045749464960b60a68ee0572033238307a2141524d3634204650204153494d442041455320564d48207c2032383635207c20348001ea1e8a010f416472656e6f2028544d29203634309201104f70656e474c20455320332e312076319a012b476f6f676c657c39646465623966372d343930302d343661342d383961382d353330326535396336326431a2010f3130332e3138322e3130362e323533aa0102656eb201203137376137396635616462353732323836386533313765653164373963333661ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d583931304eea014036363332386231313137383330313566313132643163633966326165366538306435653231666130316234326530303566386235656330653835376465666437f00101ca020b566f6461666f6e6520494ed2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003c9c302e803d59502f003d713f803be058004b5d20188048ff201900496a4029804c9c302c80402d204402f646174612f6170702f636f6d2e6474732e66726565666972656d61782d505134696367307542345544706f696d366b71472d513d3d2f6c69622f61726d3634e00402ea046066376464366430613263356535616435316139333630306662633035333863377c2f646174612f6170702f636f6d2e6474732e66726565666972656d61782d505134696367307542345544706f696d366b71472d513d3d2f626173652e61706bf00402f804028a050236349a050a32303139313134393336b205094f70656e474c455333b805ff7fc00504ca0500e005ec42ea050b616e64726f69645f6d6178f2055c4b717348542f5831335a346e486f496c566553715579443677674132374869794c78424d2b534253426b543263623866624a4d6b706d6b576e38443261334970586957536e2f2f443145477052797277786f7131772b6a705741773df805fbe4068806019006019a060134a2060134"
    )

    # replace placeholders
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
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": version
    }

    response = requests.post(url, data=payload, headers=headers)

    if response.status_code != 200:
        return None

    # extract ONLY JWT from binary response using regex
    raw = response.content.decode("latin-1", errors="ignore")

    match = re.search(
        r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        raw
    )

    if not match:
        return None

    return match.group(0)


# ----------------------------------------
# HOME ROUTE
# ----------------------------------------
@app.route("/")
def home():
    return jsonify({
        "message": "JWT API running",
        "usage": "/get_jwt_token?uid=XXX&password=XXX&version=OB52"
    })


# ----------------------------------------
# MAIN API ROUTE
# ----------------------------------------
@app.route("/get_jwt_token", methods=["GET"])
def get_jwt_token():

    uid = request.args.get("uid")
    password = request.args.get("password")
    version = request.args.get("version")

    if not uid or not password or not version:
        return jsonify({
            "status": "error",
            "message": "uid, password and version required"
        }), 400

    try:
        access_token, open_id = guest_token(uid, password)

        if not access_token:
            return jsonify({
                "status": "error",
                "message": "guest login failed"
            })

        token = MajorLogin(access_token, open_id, version)

        if not token:
            return jsonify({
                "status": "error",
                "message": "MajorLogin failed"
            })

        decoded = decode_jwt(token)

        account_info = {}
        if decoded:
            account_info = {
                "account_id": decoded.get("account_id"),
                "nickname": decoded.get("nickname"),
                "platform": decoded.get("plat_id"),
                "region": decoded.get("noti_region")
            }

        return jsonify({
            "status": "success",
            "account_info": account_info,
            "token": token
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })


if __name__ == "__main__":
    app.run(debug=True)