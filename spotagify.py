#!/usr/bin/env python3

import base64
from datetime import datetime, timedelta, tzinfo
import http.server
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

REDIRECT_SERVER_PORT = 8000
REDIRECT_TO_ADDRESS = "https://accounts.spotify.com/authorize"
NEEDED_SCOPES = [
    "playlist-read-private",
]

SPOTIFY_APP_FILE = "spotify_app.json"
TOKEN_FILE = "access_token.json"

CODE = None

class UTCtz(tzinfo):
    """UTC"""
    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)

UTC = UTCtz()


def request(method, url, params=None, data=None, headers=None, raw_response=False):
    post_data = urllib.parse.urlencode(data).encode() if data is not None else None
    query_string = urllib.parse.urlencode(params) if params is not None else None

    url_string = "%s?%s" % (url, query_string) if query_string else url

    request = urllib.request.Request(url_string, data=post_data, headers=headers, method=method)
    response_data = {}

    if raw_response:
        return urllib.request.urlopen(request)
    else:
        try:
            response = urllib.request.urlopen(request)
            response_data = json.loads(response.read().decode('UTF-8'))

            return response_data
        except urllib.error.HTTPError as error:
            print(error)
            print(error.headers)
            print(error.reason)
            raise

def get(*args, **kwargs):
    return request("GET", *args, **kwargs)

def post(*args, **kwargs):
    return request("POST", *args, **kwargs)


def request_code(client_id):
    global CODE
    class RedirectRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            request_data = urllib.parse.urlencode({
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:%s" % REDIRECT_SERVER_PORT,
                "scope": " ".join(NEEDED_SCOPES),
            })
            redirect_url = "%s?%s" % (REDIRECT_TO_ADDRESS, request_data)
            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.end_headers()

    class CodeRecieverRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            global CODE
            url_data = urllib.parse.urlparse(self.path)
            url_query = urllib.parse.parse_qs(url_data.query)

            CODE = url_query["code"][0]

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Successfully received token!\nYou can now close this window")


    server_address = ("localhost", REDIRECT_SERVER_PORT)

    server = http.server.HTTPServer(server_address, RedirectRequestHandler)
    print("Starting redirect-server on: http://%s:%s" % server_address)
    server.handle_request()
    server.server_close()

    server = http.server.HTTPServer(server_address, CodeRecieverRequestHandler)
    server.handle_request()
    print("Shutting down server")
    server.server_close()

    return CODE  # This makes me nausiated


def request_tokens(code, client_id, client_secret):
    print("Getting tokens for: " + code)
    endpoint = "https://accounts.spotify.com/api/token"
    post_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost:%s" % REDIRECT_SERVER_PORT,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    response_data = post(endpoint, data=post_data)

    expiry_date = datetime.now(tz=UTC) + timedelta(seconds=response_data.get("expires_in", 0))
    expiry_string = expiry_date.isoformat()
    response_data["expires_on"] = expiry_string.replace("+00:00", "+0000")
    response_data.pop("expires_in")

    return response_data


def refresh_token(refresh_token, client_id, client_secret):
    endpoint = "https://accounts.spotify.com/api/token"
    body_parameters = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    headers = {
        "Authorization": b"Basic " + base64.b64encode(("%s:%s" % (client_id, client_secret)).encode()),
    }

    response_data = post(endpoint, data=body_parameters, headers=headers)

    expiry_date = datetime.now(tz=UTC) + timedelta(seconds=response_data.get("expires_in", 0))
    expiry_string = expiry_date.isoformat()
    response_data["expires_on"] = expiry_string.replace("+00:00", "+0000")

    response_data.pop("expires_in")  # Replaced by expires_on

    if "refresh_token" not in response_data:
        response_data["refresh_token"] = refresh_token

    return response_data


def list_playlists(token):
    endpoint = "https://api.spotify.com/v1/me/playlists"
    headers = {
        "Authorization": "%(token_type)s %(access_token)s" % token,
    }

    total_number = 2**63 - 1  # Very high number, will be corrected after fetch
    limit = 50
    current_playlist = 0

    while current_playlist < total_number:
        query = {
            "limit": limit,
            "offset": current_playlist,
        }

        response_data = get(endpoint, params=query, headers=headers)

        total_number = response_data.get("total", 0)
        limit = response_data.get("limit", 20)


        for playlist_data in response_data.get("items", []):
            yield playlist_data
            current_playlist += 1


if __name__ == "__main__":
    client_data = {}
    with open(SPOTIFY_APP_FILE, "r") as client_file:
        client_data = json.load(client_file)

    token_data = {}
    try:
        with open(TOKEN_FILE, "r") as token_file:
            token_data = json.load(token_file)
    except FileNotFoundError:
        print("Couldn't find token file...")

    expiry_string = token_data.get("expires_on", "1900-01-01T00:00:00.000000+0000")
    token_expiry_date = datetime.strptime(expiry_string, "%Y-%m-%dT%H:%M:%S.%f%z")

    if token_expiry_date <= datetime.now(tz=UTC):
        print("Access token is out of date, requesting new...")
        code = token_data.get("refresh_token")
        if not code:
            code = request_code(client_data.get("client_id"))
            token_data = request_tokens(code, **client_data)
        else:
            token_data = refresh_token(code, **client_data)

        with open(TOKEN_FILE, "w") as token_file:
            json.dump(token_data, token_file)

    for playlist in list_playlists(token_data):
        print(playlist.get("name"))
