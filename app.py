
from flask import Flask, render_template, redirect, session, url_for, request
import os
from dotenv import load_dotenv
import json
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pip._vendor import cachecontrol
import google.auth.transport.requests
import requests
from google.oauth2 import id_token
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
GOOGLE_OAUTH_SECRETS = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
}


flow = Flow.from_client_config(
    GOOGLE_OAUTH_SECRETS,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
    redirect_uri=os.getenv("REDIRECT_URI"),
)

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return redirect(url_for("login"))
        else:
            return function()
    return wrapper

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        return redirect(url_for("login"))
    
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_OAUTH_SECRETS["web"]["client_id"]
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/")

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")

@app.route('/')
def index():
    # Jika pengguna belum login, tampilkan halaman signin
    if "google_id" not in session:
        return render_template('signin.html')
    else:
        return render_template('index.html', name=session.get("name"))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

