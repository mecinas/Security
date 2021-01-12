from flask import Flask, request, make_response, flash, g
from redis import StrictRedis
from os import getenv
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
from datetime import datetime
from jwt import encode, decode
from time import sleep
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
JWT_SECRET_SEC = getenv("JWT_SECRET_SEC")

app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = JWT_SECRET
app.debug = False


def allowed_methods(methods):
    if 'OPTIONS' not in methods:
        methods.append('OPTIONS')
    response = make_response('', 204)

    origin = request.headers.get('Origin')
    allowed_origins = ["http://localhost:8000",
                       "http://localhost:8000/", "https://localhost:8000"]
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

    data = {}
    return data


@app.route("/root/sender/register", methods=['GET', 'OPTIONS'])
def open_register():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    data = {}
    return data


@app.route("/root/sender/login", methods=['GET', 'OPTIONS'])
def open_login():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    data = {}
    return data

def authorizate(data, token):
    try:
        g.authorization = decode(token, JWT_SECRET, algorithms=['HS256'])
    except Exception as e:
        return False
    if not is_login(g.authorization.get('login')):
        return False
    data["is_authorized"] = True
    return True

@app.route("/root/sender/changePswd", methods=['GET', 'OPTIONS'])
def open_changePswd():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    data = {'is_authorized': False}
    token = request.headers.get("cookie")
    authorizate(data, token)

    return data


@app.route("/root/sender/control/answer", methods=['GET', 'OPTIONS'])
def open_check_control_answer():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    data = {'is_authorized': False}
    token = request.headers.get("cookie")
    authorizate(data, token)

    return data


@app.route("/root/sender/addNotes", methods=['GET', 'OPTIONS'])
def open_notes():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    data = {'is_authorized': False}
    token = request.headers.get("cookie")
    authorizate(data, token)

    return data


@app.route("/root/sender/recoverPswd", methods=['GET', 'OPTIONS'])
def open_recoverPswd():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    data = {}
    return data


@app.route("/root/sender/publicNotes", methods=['GET', 'OPTIONS'])
def show_public_notes():
    if request.method == "OPTIONS":
        return allowed_methods(['GET'])

    data = {
        "has_notes": False,
        "notes": None,
    }
    notes = db.hget(f"notes", "public")
    if notes is None:
        return data
    else:
        notes = json.loads(notes).get("notes")
        if notes is None:
            return data

    data["has_notes"] = True
    data["notes"] = notes
    return data


@app.route("/root/sender/privateNotes", methods=['GET', 'OPTIONS'])
def show_private_notes():
    if request.method == "OPTIONS":
        return allowed_methods(['GET'])

    data = {
        "is_authorized": False,
        "has_notes": False,
        "notes": None,
    }
    token = request.headers.get("cookie")
    if not authorizate(data, token):
        return data

    notes = db.hget(f"user:{login}", "private_notes")
    if notes is None:
        return data
    else:
        notes = json.loads(notes).get("notes")
        if notes is None:
            return data

    data["has_notes"] = True
    data["notes"] = notes
    return data


@app.route('/root/check/<login>', methods=['GET', 'OPTIONS'])
def check_login(login):
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])
    print(login)
    data = {login: "available"}
    if is_login(login):
        data = {login: "taken"}

    response = make_response(data, 200)
    origin = request.headers.get('Origin')
    allowed_origins = ["http://localhost:8000", "http://localhost:8000/"]
    if origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin

    return response


@app.route('/root/recover/check/<login>', methods=['GET', 'OPTIONS'])
def check_recover_login(login):
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])

    data = {
        "availability": "taken",
        "cookie": None,
        "question": None
    }
    if not is_login(login):
        data["availability"] = "available"
        return data

    payload = {
        "login": login,
        "access_granted": True
    }
    data["cookie"] = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    data["question"] = db.hget(f"user:{login}", "question")
    return data


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
        f"user:{login}", "password")
    if not hashed_password_database:
        return False
    print(checkpw(password_encoded, hashed_password_database.encode('utf-8')))
    
    return checkpw(password_encoded, hashed_password_database.encode('utf-8'))

def save_user(firstname, lastname, login, password, question, answer):
    salt = gensalt(5)
    password_encoded = password.encode()
    hashed_password = hashpw(password_encoded, salt)

    answer_encoded = answer.encode()
    hashed_answer = hashpw(answer_encoded, salt)
    db.hset(f"user:{login}", "firstname", firstname)
    db.hset(f"user:{login}", "lastname", lastname)
    db.hset(f"user:{login}", "password", hashed_password)
    db.hset(f"user:{login}", "question", question)
    db.hset(f"user:{login}", "answer", hashed_answer)


def validate_input(firstname, lastname, login, password, sec_password, question, answer):
    valid_input = False
    data = {
        "valid_input": valid_input,
    }

    if sec_password != password:
        return data
    if firstname and lastname and login and password:
        if is_login(login):
            return data

        save_user(firstname, lastname, login, password, question, answer)
        valid_input = True
        data["valid_input"] = valid_input
        return data

    return data


@app.route("/root/sender/register", methods=['POST'])
def register():
    cli_data = request.json
    firstname = cli_data.get('firstname')
    lastname = cli_data.get('lastname')
    login = cli_data.get('login')
    password = cli_data.get('password')
    sec_password = cli_data.get('sec_password')
    question = cli_data.get('question')
    answer = cli_data.get('answer')

    return validate_input(firstname, lastname,
                          login, password, sec_password, question, answer)

def set_delay(data, delay_cookie=None):
    data["is_valid"] = False
    delay=1
    payload = {
        "delay_time":delay
    }
    if delay_cookie is not None:
        decoded = None
        try:
            decoded = decode(delay_cookie, JWT_SECRET, algorithms=['HS256'])
        except Exception as e:
            delay = 200
            payload["delay"] = delay
            return False
        delay = pow(decoded.get("delay_time")+0.1,2)
        payload["delay_time"] = delay
    sleep(delay)
    cookie = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    data["cookie"] = cookie
    return True

@app.route("/root/sender/login", methods=['POST'])
def login():
    cli_data = request.json
    login = cli_data.get('login')
    password = cli_data.get('password')
    delay_cookie = request.headers.get("delay_cookie")

    messages = []
    data = {
        "messages": messages,
        "is_valid": True,
        "cookie": None
    }
    if not verify_user(login, password):
        messages.append("Podano nieprawidłowy login lub hasło")
        if not set_delay(data, delay_cookie):
            messages.append("Wykryto próbę ataku na ciasteczko")
            return data
        return data

    messages.append("Zalogowano!")
    payload = {
        "login": login,
        "date": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    }
    cookie = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    data["cookie"] = cookie
    return data


@app.route("/root/sender/changePswd", methods=['POST'])
def post_changePswd():
    cli_data = request.json
    old_pswd = cli_data.get('old_pswd')
    new_pswd = cli_data.get('new_pswd')
    new_pswd2 = cli_data.get('new_pswd2')

    messages = []
    data = {
        'messages': messages,
        'is_authorized': False
    }
    token = request.headers.get("cookie")
    if not authorizate(data, token):
        return data
    login = g.authorization.get("login")
    if not verify_user(login, old_pswd):
        messages.append("Podane hasło jest nieprawidłowe")
        return data
    if new_pswd != new_pswd2:
        messages.append("Nowe hasła są różne")
        return data

    messages.append("Hasło zostało zmienione")
    salt = gensalt(5)
    password_encoded = new_pswd.encode()
    hashed_password = hashpw(password_encoded, salt)
    db.hset(f"user:{login}", "password", hashed_password)

    return data


@app.route('/root/sender/validate/answer', methods=['POST'])
def post_validate_answer():
    answer = request.json.get("answer")
    token = request.headers.get('cookie')

    data = {
        "is_authorized": False,
        "is_valid": False,
        "cookie": None
    }

    if not authorizate(data, token):
        return data
    login = g.authorization.get("login")

    answer_encoded = answer.encode('utf-8')
    hashed_answer_database = db.hget(
        f"user:{login}", "answer")
    if not hashed_answer_database:
        return data
    if not checkpw(answer_encoded, hashed_answer_database.encode('utf-8')):
        return data
    data["is_valid"] = True

    payload = {
        "login": login,
        "is_valid": True
    }
    data["cookie"] = jwt.encode(
        payload, JWT_SECRET, algorithm='HS256')
    return data


@app.route('/root/sender/recover/changePswd', methods=['POST'])
def post_recover_changePswd():
    password = request.json.get("new_pswd")
    token = request.headers.get('cookie')

    data = {
        "is_authorized": False,
        "is_success": False,
    }
    if not authorizate(data, token):
        return data
    login = g.authorization.get("login")

    salt = gensalt(5)
    password_encoded = password.encode()
    hashed_password = hashpw(password_encoded, salt)

    db.hset(f"user:{login}", "password", hashed_password)
    data["is_success"] = True

    return data


@app.route('/root/sender/addNotes', methods=['POST'])
def post_notes():
    cli_data = request.json
    token = request.headers.get('cookie')
    data = {
        "is_authorized": False
    }
    print("1111")
    if not authorizate(data, token):
        print("2222")
        return data

    input_note = cli_data.get('note')
    db_notes = {}
    if cli_data.get('access') == 'private':
        db_notes = db.hget(f"user{login}", "private_notes")
    else:
        db_notes = db.hget(f"notes", "public")

    new_notes = {"notes": []}
    if db_notes is None:
        new_notes["notes"].append(input_note)
    else:
        new_notes = json.loads(db_notes)
        new_notes["notes"].append(input_note)

    new_notes = json.dumps(new_notes)
    if cli_data.get('access') == 'private':
        db.hset(f"user:{login}", 'private_notes', new_notes)
    else:
        db.hset(f"notes", 'public', new_notes)
    data["is_authorized"] = True
    return data


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=6000)
