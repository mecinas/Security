from flask import Flask, request, make_response, flash, g
from redis import StrictRedis
from os import getenv
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
from datetime import datetime
from jwt import encode, decode
import jwt
from uuid import uuid4
import json

load_dotenv()
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
db = StrictRedis(REDIS_HOST, db=16, password=REDIS_PASS, decode_responses=True)
SESSION_REDIS = db
SESSION_TYPE = 'filesystem'

SESSION_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_HTTPONLY = True
JWT_SECRET = getenv("JWT_SECRET")

app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = JWT_SECRET
app.debug = False


def allowed_methods(methods):
    if 'OPTIONS' not in methods:
        methods.append('OPTIONS')
    response = make_response('', 204)

    origin = request.headers.get('Origin')
    allowed_origins = ["http://localhost:8000", "http://localhost:8000/"]
    if origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin

    response.headers['Access-Control-Allow-Methods'] = ', '.join(methods)
    response.headers["Access-Control-Allow-Headers"] = 'Content-Type, auth_cookie'
    response.headers["Access-Control-Allow-Credentials"] = 'true'
    return response


@app.route('/root', methods=['GET', 'OPTIONS'])
def root():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET'])

    links = []
    links.append({"type": 'register', "url": '/sender/register'})
    links.append({"type": 'login', "url": '/sender/login'})

    document = {
        "data": {},
        "links": links
    }
    return document


@app.route("/root/sender/register", methods=['GET', 'OPTIONS'])
def open_register():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    links = []
    links.append({"type": 'root:parent', "url": '/'})
    document = {
        "data": {},
        "links": links
    }
    return document


@app.route("/root/sender/login", methods=['GET', 'OPTIONS'])
def open_login():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    links = []
    links.append({"type": 'root:parent', "url": '/'})
    document = {
        "data": {},
        "links": links
    }
    return document

@app.route('/root/check/<login>', methods=['GET', 'OPTIONS'])
def check_login(login):
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])
    
    result = {login: "available"}
    if is_login(login):
        result = {login: "taken"}

    response = make_response(result, 200)
    origin = request.headers.get('Origin')
    allowed_origins = ["http://localhost:8000", "http://localhost:8000/"]
    if origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
    return response

def convert_to_output_packages(all_packages, packages_for_response):
    for (f_key, f_value) in all_packages.items():
        if f_value is not None:
            for (s_key, s_value) in json.loads(f_value).items():
                single_package = {
                    "sender_name": f_key[5:],
                    "id": s_key,
                    "adressee_name": s_value["adressee_name"],
                    "storeroom_id": s_value["storeroom_id"],
                    "size": s_value["size"],
                    "state": s_value["state"]
                }
                packages_for_response.append(single_package)

def is_login(login):
    return db.hexists(f"user:{login}", "password")


def verify_user(login, password):
    password_encoded = password.encode('utf-8')
    hashed_password_database = db.hget(
        f"user:{login}", "password").encode('utf-8')
    if not hashed_password_database:
        return False
    return checkpw(password_encoded, hashed_password_database)


def save_user(firstname, lastname, email, adress, login, password):
    salt = gensalt(5)
    password_encoded = password.encode()
    hashed_password = hashpw(password_encoded, salt)
    db.hset(f"user:{login}", "firstname", firstname)
    db.hset(f"user:{login}", "lastname", lastname)
    db.hset(f"user:{login}", "email", email)
    db.hset(f"user:{login}", "adress", adress)
    db.hset(f"user:{login}", "password", hashed_password)


def validate_input(firstname, lastname, email, adress, login, password, sec_password):
    valid_input = False
    data = {
        "valid_input": valid_input,
    }
    links = []
    links.append({"type": 'root:parent', "url": '/'})
    document = {
        "data": data,
        "links": links
    }
    if sec_password != password:
        return document
    if firstname and lastname and email and adress and login and password:
        if is_login(login):
            return document

        save_user(firstname, lastname, email, adress, login, password)
        valid_input = True
        data["valid_input"] = valid_input
        return document

    return document


@app.route("/root/sender/register", methods=['POST'])
def register():
    data = request.json
    firstname = data.get('firstname')
    lastname = data.get('lastname')
    email = data.get('email')
    adress = data.get('adress')
    login = data.get('login')
    password = data.get('password')
    sec_password = data.get('sec_password')

    return validate_input(firstname, lastname, email, adress,
                          login, password, sec_password)


@app.route("/root/sender/login", methods=['POST'])
def login():
    data = request.json
    login = data.get('login')
    password = data.get('password')

    messages = []
    is_valid = True
    links = []
    links.append({"type": 'root:parent', "url": '/'})
    data = {
        "messages": messages,
        "is_valid": is_valid,
        "cookies": None
    }
    document = {
        "data": data,
        "links": links
    }
    if not verify_user(login, password):
        messages.append("Podano nieprawidłowy login lub hasło")
        is_valid = False
        data["is_valid"] = is_valid
        return document

    messages.append("Zalogowano!")
    payload = {
        "login": login,
        "date": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    }
    cookie = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    document["data"]["cookies"] = cookie
    return document

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=6000)
