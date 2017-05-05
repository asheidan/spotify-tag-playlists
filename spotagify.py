#!/usr/bin/env python3

import argparse
import base64
from datetime import datetime, timedelta, tzinfo
import http.server
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_REDIRECT_SERVER_PORT = 8000
REDIRECT_TO_ADDRESS = "https://accounts.spotify.com/authorize"
NEEDED_SCOPES = [
    "playlist-read-private",
]

DEFAULT_SPOTIFY_APP_FILE = "spotify_app.json"
DEFAULT_TOKEN_FILE = "access_token.json"

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


def request_code(options: argparse.Namespace):
    global CODE
    class RedirectRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            request_data = urllib.parse.urlencode({
                "client_id": options.spotify_data["client_id"],
                "response_type": "code",
                "redirect_uri": "http://localhost:%s" % options.redirect_server_port,
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

    server_address = ("localhost", options.redirect_server_port)

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


def local_token_validation(options: argparse.Namespace) -> None:
    if options.token_data["expires_on"] >= datetime.now(tz=UTC):
        print("Token is valid")
    else:
        print("Token is invalid. You need to request a new token or refresh this one.")


def parse_json_from_file(filename: str) -> dict:
    data = {}
    try:
        with open(filename, "r") as json_file:
            data =  json.load(json_file)
    except FileNotFoundError:
        pass

    return data


def parse_token_data_from_file(filename: str) -> dict:
    token_data = parse_json_from_file(filename)

    expiry_string = token_data.get("expires_on", "1900-01-01T00:00:00.000000+0000")
    token_expiry_date = datetime.strptime(expiry_string, "%Y-%m-%dT%H:%M:%S.%f%z")

    token_data["expires_on"] = token_expiry_date

    return token_data


# TUI #########################################################################

def parse_arguments(arguments: [str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.set_defaults(function=lambda _: parser.print_usage())

    parser.add_argument("--spotify-file", action="store", type=parse_json_from_file,
                        dest="spotify_data", default=DEFAULT_SPOTIFY_APP_FILE,
                        metavar="FILE", help="The file to use for storing secret app key.")
    parser.add_argument("--token-file", action="store", type=parse_token_data_from_file,
                        dest="token_data", default=DEFAULT_TOKEN_FILE,
                        metavar="FILE", help="The file to use for storing token information.")

    subparsers = parser.add_subparsers(title="Subcommands")

    # Tokens ##################################################################
    token_parser = subparsers.add_parser("token", help="Handle authentication tokens")
    token_parser.set_defaults(function=lambda _: token_parser.print_usage())
    token_subparsers = token_parser.add_subparsers(title="Token management commands")

    token_request_parser = token_subparsers.add_parser("request", help="Request new token, both access- and refresh-token.")
    token_request_parser.add_argument("--port",
                                      action="store", type=int, dest="redirect_server_port", metavar="PORT",
                                      default=DEFAULT_REDIRECT_SERVER_PORT,
                                      help=("Server port to use for the local redirect server."
                                            " Default is %d." % DEFAULT_REDIRECT_SERVER_PORT))
    token_request_parser.set_defaults(function=request_code)

    token_refresh_parser = token_subparsers.add_parser("refresh", help="Refresh access-token using existing refresh-token")

    token_validation_parser = token_subparsers.add_parser("validate", help="Check if the current token is valid")
    token_validation_parser.set_defaults(function=local_token_validation)

    # Tags ####################################################################
    tag_parser = subparsers.add_parser("tags", help="Manage tags")
    tag_parser.set_defaults(function=lambda _: tag_parser.print_usage())
    tag_subparsers = tag_parser.add_subparsers(title="Tag management commands")

    tag_list_parser = tag_subparsers.add_parser("list", help="List current tags in local cache.")

    tag_pull_parser = tag_subparsers.add_parser("pull", help="Pull current tags from Spotify.")

    tag_push_parser = tag_subparsers.add_parser("push", help="Push current tags to Spotify.")

    # Playlists ###############################################################
    playlist_parser = subparsers.add_parser("playlists", help="Manage playlists")
    playlist_parser.set_defaults(function=lambda _: playlist_parser.print_usage())
    playlist_subparsers = playlist_parser.add_subparsers(title="Playlist commands")

    playlist_create_parser = playlist_subparsers.add_parser("create", help="Create a new (smart) playlist.")
    playlist_create_parser.set_defaults(function=lambda _: playlist_create_parser.print_usage())

    options = parser.parse_args(arguments)

    return options


if __name__ == "__main__":
    options = parse_arguments(sys.argv[1:])

    options.function(options)


if False:
    client_data = {}
    with open(options.spotify_file, "r") as client_file:
        client_data = json.load(client_file)

    token_data = {}
    try:
        with open(options.token_file, "r") as token_file:
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
