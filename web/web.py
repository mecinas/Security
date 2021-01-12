from flask import Flask, request, make_response, render_template, flash
import requests
from os import getenv
from dotenv import load_dotenv
from datetime import datetime
from uuid import uuid4
import json

#zrobić plik .sock
#Atak od strony postman, ponowna walidacja danych od walidowanych przez js

load_dotenv()
SESSION_TYPE = 'filesystem'
SESSION_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_HTTPONLY = True

app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')
app.debug = False
WEB_SEVICE_URL = "https://whispering-escarpment-15779.herokuapp.com"

def direct_get_render(url, html_resource, token, data={}, special_token_name=None, kill_cookie_name=None):
    api_response = requests.get(url)
    if(api_response.status_code >= 400):
        return make_response('Błąd w połączeniu z serwerem', 500)
    client_response = make_response(render_template(html_resource, **data))
    if token is not None:
        if special_token_name is not None:
            client_response.set_cookie(special_token_name, token)
        else:
            client_response.set_cookie('auth', token, max_age=20)
    if kill_cookie_name is not None:
        client_response.delete_cookie(kill_cookie_name)
    return client_response

def auth_valid_response(api_response):
    if(api_response.status_code >= 400):
        return make_response('Błąd w połączeniu z serwerem', 500)
    api_response = json.loads(api_response.content)
    if(api_response.get('is_authorized') == False):
        return make_response("Brak dostępu, aby przejść do tego panelu należy uprzednio się zalogować", 401)
    return False

def auth_get_render(url, html_resource, token, data={}):
    cookie = {"cookie": token}
    api_response = requests.get(url, headers=cookie)

    if auth_valid_response(api_response):
        return auth_valid_response(api_response)

    cookie = token
    client_response = make_response(render_template(html_resource, **data))
    client_response.set_cookie('auth', cookie, max_age=20)

    return client_response

@app.route('/', methods=['GET'])
def open_home():
    url = WEB_SEVICE_URL + "/root"
    return direct_get_render(url, "home.html", request.cookies.get('auth'))

@app.route("/sender/register", methods=['GET'])
def open_register():
    url = WEB_SEVICE_URL + "/root/sender/register"
    return direct_get_render(url, "register.html", request.cookies.get('auth'))

@app.route("/sender/login", methods=['GET'])
def open_login():
    url = WEB_SEVICE_URL + "/root/sender/login"
    return direct_get_render(url, "login.html", request.cookies.get('auth'))

@app.route("/sender/addNotes", methods=['GET'])
def open_add_notes():
    url = WEB_SEVICE_URL + "/root/sender/addNotes"
    return auth_get_render(url, "addNotes.html", request.cookies.get('auth'))

@app.route("/sender/changePswd", methods=['GET'])
def open_changePswd():
    url = WEB_SEVICE_URL + "/root/sender/changePswd"
    return auth_get_render(url, "changePswd.html", request.cookies.get('auth'))

@app.route("/sender/recoverPswd", methods=['GET'])
def open_recoverPswd():
    url = WEB_SEVICE_URL + "/root/sender/recoverPswd"
    return direct_get_render(url, "recoverVerify.html", request.cookies.get('auth'))

@app.route("/sender/publicNotes", methods=['GET'])
def open_public_notes():
    url = WEB_SEVICE_URL + "/root/sender/publicNotes"

    api_response = requests.get(url)
    if(api_response.status_code >= 400):
        return make_response('Błąd w połączeniu z serwerem', 500)
    api_response_data = json.loads(api_response.content)
    cookie = request.cookies.get('auth')

    data = {
        "has_notes": api_response_data["has_notes"],
        "notes": api_response_data["notes"]
    }

    return direct_get_render(url, "publicNotes.html", request.cookies.get('auth'), data)

@app.route("/sender/privateNotes", methods=['GET'])
def open_private_notes():
    url = WEB_SEVICE_URL + "/root/sender/privateNotes"
    cookie = {"cookie": request.cookies.get('auth')}
    api_response = requests.get(url, headers=cookie)

    if(api_response.status_code >= 400):
        return make_response('Błąd w połączeniu z serwerem', 500)
    api_response_data = json.loads(api_response.content)

    data = {
        "has_notes": api_response_data["has_notes"],
        "notes": api_response_data["notes"]
    }

    return auth_get_render(url, "privateNotes.html", request.cookies.get('auth'), data)

@app.route("/sender/logout", methods=['GET'])
def open_logout():
    client_response = make_response(render_template("login.html"))
    client_response.delete_cookie('auth')
    return client_response

@app.route("/sender/register", methods=['POST'])
def post_register():
    data = {
        "firstname": request.form.get('firstname'),
        "lastname": request.form.get('lastname'),
        "login": request.form.get('login'),
        "password": request.form.get('password'),
        "sec_password": request.form.get('sec_password'),
        "question": request.form.get('question'),
        "answer": request.form.get('answer')
    }

    url = WEB_SEVICE_URL + "/root/sender/register"
    api_response = requests.post(url, json=data)
    if(api_response.status_code >= 400):
        return make_response('Błąd w połączeniu z serwerem', 500)
    flash("Poprawnie zarejestrowano")
    return direct_get_render(url, "register.html", request.cookies.get('auth'))


@app.route("/sender/login", methods=['POST'])
def post_login():
    data = {
        "login": request.form.get("login"),
        "password": request.form.get("password")
    }
    url = WEB_SEVICE_URL + "/root/sender/login"
    cookie = {"delay_cookie": request.cookies.get('delay_cookie')}
    api_response = requests.post(url, headers=cookie, json=data)

    if(api_response.status_code >= 400):
        return make_response('Błąd w połączeniu z serwerem', 500)

    api_data = json.loads(api_response.content)
    for message in api_data["messages"]:
        flash(message)

    if not api_data.get("is_valid"):
        api_cookie = bytes(api_data["cookie"], 'utf-8')
        return direct_get_render(url, "login.html", api_cookie, special_token_name="delay_cookie")
    api_cookie = bytes(api_data["cookie"], 'utf-8')

    return direct_get_render(url, "login.html", api_cookie, kill_cookie_name="delay_cookie")

@app.route("/sender/changePswd", methods=['POST'])
def post_changePswd():
    url = WEB_SEVICE_URL + "/root/sender/changePswd"
    data = {
        "old_pswd": request.form.get("old_pswd"),
        "new_pswd": request.form.get("new_pswd"),
        "new_pswd2": request.form.get("new_pswd2")
    }
    cookie = {"cookie": request.cookies.get('auth')}
    api_response = requests.post(url=url, headers=cookie, json=data)
    if auth_valid_response(api_response):
        return auth_valid_response(api_response)
    api_response_data = json.loads(api_response.content)
    for message in api_response_data.get('messages'):
        flash(message)
    return open_login()

@app.route("/sender/recoverPswd", methods=['POST'])
def post_recoverPswd():
    login = request.form.get("login")
    url = WEB_SEVICE_URL + "/root/recover/check/" + login
    api_response = requests.get(url=url)

    if(api_response.status_code >= 400):
        return make_response('Błąd w połączeniu z serwerem', 500)

    api_response_data = json.loads(api_response.content)
    if api_response_data.get("availability") == "available":
        flash("Podany login nie istnieje")
        return open_recoverPswd()

    question = api_response_data.get("question")
    cookie = api_response_data.get("cookie")
    client_response = make_response(render_template("recoverQuestion.html", question=question))
    client_response.set_cookie('recover_token', cookie, max_age=20)
    return client_response

@app.route("/sender/validate/answer", methods=['POST'])
def post_validate_answer():
    answer = request.form.get("answer")
    url = WEB_SEVICE_URL + "/root/sender/validate/answer"
    cookie = {"cookie": request.cookies.get('recover_token')}
    data = {"answer": answer}

    api_response = requests.post(url=url, headers=cookie, json=data)
    if auth_valid_response(api_response):
        return auth_valid_response(api_response)
    
    api_response_data = json.loads(api_response.content)
    if(api_response_data.get("is_valid") == False):
        flash("Podano nieprawidłową odpowiedź")
        return open_recoverPswd()
    
    cookie = api_response_data.get("cookie")
    client_response = make_response(render_template("recoverChangePswd.html"))
    client_response.set_cookie('change_Pswd_token', cookie, max_age=20)
    return client_response

@app.route("/sender/recover/changePswd", methods=['POST'])
def post_recover_changePswd():
    new_pswd = request.form.get("new_pswd")
    new_pswd2 = request.form.get("new_pswd2")

    url = WEB_SEVICE_URL + "/root/sender/recover/changePswd"
    cookie = {"cookie": request.cookies.get('change_Pswd_token')}
    data = {
        "new_pswd": new_pswd,
    }
    api_response = requests.post(url=url, headers=cookie, json=data)
    if auth_valid_response(api_response):
        return auth_valid_response(api_response)
    
    api_response_data = json.loads(api_response.content)
    if(api_response_data.get("is_success") == False):
        flash("Problem z zapisem hasła")
        return open_recoverPswd()
    flash("Hasło zostało zmienione")
    return open_login()

@app.route("/sender/addNotes", methods=['POST'])
def post_notes():
    url = WEB_SEVICE_URL + "/root/sender/addNotes"
    data = {
        'note':request.form.get('note'),
        'access':request.form.get('access')
        }
    cookie = {"cookie": request.cookies.get('auth')}

    api_response = requests.post(url=url, headers=cookie, json=data)
    if auth_valid_response(api_response):
        return auth_valid_response(api_response)
    
    flash("Dodano notatkę")
    return open_add_notes()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000)
