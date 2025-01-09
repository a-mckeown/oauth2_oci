from flask import Flask, request, redirect, render_template, url_for, jsonify
import requests # For HTTP Requests
import json
import jwt  # PyJWT for decoding ID tokens
from urllib.parse import urlencode

app = Flask(__name__)

# Configuration for OAuth 2.0 and OpenID Connect
config = {
    "client_id": "google-client-id",
    "client_secret": "google-client-secret",
    "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_url": "https://oauth2.googleapis.com/token",
    "redirect_uri": "http://localhost:5000/callback",
    "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
}

# The required values for testing

# client_id: A unique identifier for your app, issued by the IdP.
# client_secret: A secret key used to authenticate your app (keep it secure).
# Authorization URL (auth_url): The endpoint for initiating the OAuth flow.
# Token URL (token_url): The endpoint for exchanging authorization codes for tokens.
# Redirect URI: The URL where the provider will redirect users after they authenticate.
# UserInfo Endpoint (userinfo_endpoint): The endpoint for fetching user profile information (OpenID Connect).

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-auth')
def start_auth():
    """Starts the Authorization Code flow."""
    params = {
        "response_type": "code",
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "scope": "openid profile email",
    }
    auth_request_url = f"{config['auth_url']}?{urlencode(params)}"
    return redirect(auth_request_url)

@app.route('/callback')
def callback():
    """Handles the callback with the authorization code."""
    auth_code = request.args.get('code')
    if not auth_code:
        return "Error: No authorization code provided!", 400

    # Exchange the authorization code for an access token
    data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": config["redirect_uri"],
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
    }
    response = requests.post(config["token_url"], data=data)
    if response.status_code == 200:
        token_response = response.json()

        # Decode ID token if present
        id_token = token_response.get("id_token")
        userinfo = None
        if id_token:
            try:
                decoded_token = jwt.decode(id_token, options={"verify_signature": False})  # For debugging purposes
                userinfo = decoded_token
            except Exception as e:
                userinfo = f"Error decoding ID token: {str(e)}"

        return render_template('result.html', result=token_response, userinfo=userinfo)
    else:
        return f"Error exchanging code: {response.text}", 400

@app.route('/userinfo')
def userinfo():
    """Fetches user info using the UserInfo endpoint."""
    access_token = request.args.get('access_token')
    if not access_token:
        return "Error: No access token provided!", 400

    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(config["userinfo_endpoint"], headers=headers)
    if response.status_code == 200:
        userinfo_response = response.json()
        return render_template('result.html', result=userinfo_response)
    else:
        return f"Error fetching userinfo: {response.text}", 400

@app.route('/client-credentials')
def client_credentials():
    """Performs the Client Credentials flow."""
    data = {
        "grant_type": "client_credentials",
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "scope": "read write",
    }
    response = requests.post(config["token_url"], data=data)
    if response.status_code == 200:
        token_response = response.json()
        return render_template('result.html', result=token_response)
    else:
        return f"Error: {response.text}", 400

@app.route('/password-grant', methods=['POST'])
def password_grant():
    """Performs the Resource Owner Password Credentials flow."""
    username = request.form.get('username')
    password = request.form.get('password')

    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "scope": "read write",
    }
    response = requests.post(config["token_url"], data=data)
    if response.status_code == 200:
        token_response = response.json()
        return render_template('result.html', result=token_response)
    else:
        return f"Error: {response.text}", 400

@app.route('/config', methods=['GET', 'POST'])
def update_config():
    """Update or view the OAuth 2.0 configuration."""
    if request.method == 'POST':
        config["client_id"] = request.form.get('client_id')
        config["client_secret"] = request.form.get('client_secret')
        config["auth_url"] = request.form.get('auth_url')
        config["token_url"] = request.form.get('token_url')
        config["userinfo_endpoint"] = request.form.get('userinfo_endpoint')
        return "Configuration updated successfully!", 200
    return render_template('config.html', config=config)

if __name__ == '__main__':
    app.run(debug=True)
