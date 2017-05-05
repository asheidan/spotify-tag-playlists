#!/usr/bin/env python3

import argparse
import base64
from datetime import datetime, timedelta, tzinfo
import http.server
import json
import logging
import sqlite3
import sys
from typing import Iterator
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_REDIRECT_SERVER_PORT = 8000
REDIRECT_TO_ADDRESS = "https://accounts.spotify.com/authorize"
NEEDED_SCOPES = [
    "playlist-read-private",
]

DEFAULT_CACHE_FILE = "cache.db"
DEFAULT_SPOTIFY_APP_FILE = "spotify_app.json"
DEFAULT_TOKEN_FILE = "access_token.json"


# Globals #####################################################################

OPTIONS = argparse.Namespace()

_code = None  # Used to escape class scope in redirect server handlers


class UTCtz(tzinfo):
    """UTC"""
    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)

UTC = UTCtz()


# HTTP ########################################################################
http_logger = logging.getLogger("spotagify.http")

def request(method, url, params=None, data=None, headers=None, raw_response=False):
    post_data = urllib.parse.urlencode(data).encode() if data is not None else None
    query_string = urllib.parse.urlencode(params) if params is not None else None
    headers = headers or {}

    url_string = "%s?%s" % (url, query_string) if query_string else url

    http_logger.info("%s %s q=%s b=%s", method, url, params, data)

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


# Authentication ##############################################################

def request_code(client_id: str, redirect_server_port: int) -> str:
    global _code

    class RedirectRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            request_data = urllib.parse.urlencode({
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:%s" % redirect_server_port,
                "scope": " ".join(NEEDED_SCOPES),
            })
            redirect_url = "%s?%s" % (REDIRECT_TO_ADDRESS, request_data)
            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.end_headers()

    class CodeRecieverRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            global _code
            url_data = urllib.parse.urlparse(self.path)
            url_query = urllib.parse.parse_qs(url_data.query)

            _code = url_query["code"][0]

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Successfully received token!\nYou can now close this window.")

    server_address = ("localhost", redirect_server_port)

    server = http.server.HTTPServer(server_address, RedirectRequestHandler)
    print("Starting redirect-server on: http://%s:%s" % server_address)
    server.handle_request()
    server.server_close()

    server = http.server.HTTPServer(server_address, CodeRecieverRequestHandler)
    server.handle_request()
    print("Shutting down server")
    server.server_close()

    return _code  # This makes me nausiated


def request_tokens(code, client_id, client_secret, redirect_server_port):
    print("Getting tokens for: " + code)
    endpoint = "https://accounts.spotify.com/api/token"
    post_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost:%s" % redirect_server_port,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    response_data = post(endpoint, data=post_data)

    expiry_date = datetime.now(tz=UTC) + timedelta(seconds=response_data.get("expires_in", 0))
    expiry_string = expiry_date.isoformat()
    response_data["expires_on"] = expiry_string.replace("+00:00", "+0000")
    response_data.pop("expires_in")

    return response_data


def refresh_token(refresh_token: str, client_id: str, client_secret: str) -> dict:
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


# DB ##########################################################################

db_logger = logging.getLogger("spotagify.db")


def tidy_sql(sql: str) -> str:
    return " ".join((line.strip() for line in sql.splitlines()))


def db_connection(options: argparse.Namespace=OPTIONS) -> sqlite3.Connection:
    if hasattr(db_connection, "connection"):
        return db_connection.connection

    db_connection.connection = sqlite3.connect(options.cache_url)

    create_tables_in_database(db_cursor(db_connection.connection))

    return db_connection.connection


def db_cursor(connection: sqlite3.Connection=None) -> sqlite3.Cursor:
    connection = connection or db_connection()
    cursor = connection.cursor()
    return cursor


def db_execute(sql: str, *args, cursor: sqlite3.Cursor=None, **kwargs) -> sqlite3.Cursor:
    cursor = cursor or db_cursor()

    sql_query = tidy_sql(sql)

    db_logger.debug(sql_query)
    if len(args):
        db_logger.debug(args)

    cursor.execute(sql, args, **kwargs)

    return cursor


def create_tables_in_database(cursor: sqlite3.Cursor=None) -> None:
    cursor = cursor or db_cursor()

    db_execute("""SELECT name FROM sqlite_master WHERE type=?;""", "table", cursor=cursor)
    existing_tables = frozenset(map(lambda row: row[0], cursor))

    if "playlists" not in existing_tables:
        db_execute("""CREATE TABLE playlists (
                              id TEXT PRIMARY KEY NOT NULL,
                              name TEXT,
                              snapshot_id TEXT,
                              href TEXT);""",
                   cursor=cursor)

    if "artists" not in existing_tables:
        db_execute("""CREATE TABLE artists (
                              id TEXT PRIMARY KEY NOT NULL,
                              name TEXT,
                              type TEXT);""",
                   cursor=cursor)

    if "albums" not in existing_tables:
        db_execute("""CREATE TABLE albums (
                              id TEXT PRIMARY KEY NOT NULL,
                              name TEXT,
                              type TEXT);""",
                   cursor=cursor)

    if "album_artists" not in existing_tables:
        db_execute("""CREATE TABLE album_artists (
                              album_id TEXT, artist_id TEXT,
                              FOREIGN KEY (album_id) REFERENCES albums(id),
                              FOREIGN KEY (artist_id) REFERENCES artists(id));""",
                   cursor=cursor)

    if "songs" not in existing_tables:
        db_execute("""CREATE TABLE songs (
                              id TEXT PRIMARY KEY NOT NULL,
                              artist_id TEXT);""",
                   cursor=cursor)

    if "song_artists" not in existing_tables:
        db_execute("""CREATE TABLE song_artists (
                              song_id TEXT, artist_id TEXT,
                              FOREIGN KEY (song_id) REFERENCES songs(id),
                              FOREIGN KEY (artist_id) REFERENCES artists(id));""",
                   cursor=cursor)

    cursor.connection.commit()


def save_playlist_in_db(playlist: dict, cursor: sqlite3.Cursor=None) -> None:
    db_logger.info("Saving playlist: %(name)s" % playlist)

    cursor = db_execute("INSERT OR REPLACE INTO playlists(id, name, snapshot_id, href) VALUES(?, ?, ?, ?);",
                        playlist["id"], playlist["name"], playlist["snapshot_id"], playlist["href"],
                        cursor=cursor)

    cursor.connection.commit()


# Playlists ###################################################################

def list_playlists(token: str) -> Iterator[dict]:
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


def list_tracks_for_playlist(playlist: dict) -> Iterator[dict]:
    tracks_url = playlist.get("tracks", {}).get("href")


###############################################################################

def parse_json_from_file(filename: str) -> dict:
    data = {}
    try:
        with open(filename, "r") as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        pass

    return data


def parse_token_data_from_file(filename: str) -> dict:
    token_data = parse_json_from_file(filename)

    expiry_string = token_data.get("expires_on", "1900-01-01T00:00:00.000000+0000")
    token_expiry_date = datetime.strptime(expiry_string, "%Y-%m-%dT%H:%M:%S.%f%z")

    token_data["expires_on"] = token_expiry_date

    return token_data


# CLI #########################################################################

def local_token_validation_command(options: argparse.Namespace) -> None:
    if (
            options.token_data["expires_on"] >= datetime.now(tz=UTC) and
            "access_token" in options.token_data and
            "refresh_token" in options.token_data
    ):
        print("Token is valid")
    else:
        print("Token is invalid. You need to request a new token or refresh this one.")


def request_token_command(options: argparse.Namespace) -> None:
    token_data = options.token_data
    spotify_data = options.spotify_data

    if "client_id" not in spotify_data:
        print("Client data is invalid, missing client_id")
        sys.exit(1)

    if "client_secret" not in spotify_data:
        print("Client data is invalid, missing client_secret")
        sys.exit(1)

    token_code = request_code(spotify_data["client_id"], options.redirect_server_port)

    token_data = request_tokens(code=token_code, client_id=spotify_data["client_id"],
                                client_secret=spotify_data["client_secret"],
                                redirect_server_port=options.redirect_server_port)

    options.token_data = token_data

    with open(options.token_path, "w") as token_file:
        json.dump(token_data, token_file)


def refresh_token_command(options: argparse.Namespace) -> None:
    token_data = options.token_data
    spotify_data = options.spotify_data

    if "client_id" not in spotify_data:
        print("Client data is invalid, missing client_id")
        sys.exit(1)

    if "client_secret" not in spotify_data:
        print("Client data is invalid, missing client_secret")
        sys.exit(1)

    token_data = refresh_token(refresh_token=token_data["refresh_token"],
                               client_id=spotify_data["client_id"],
                               client_secret=spotify_data["client_secret"])

    with open(options.token_path, "w") as token_file:
        json.dump(token_data, token_file)



def pull_tags_command(options: argparse.Namespace) -> None:
    for playlist in list_playlists(options.token_data):
        playlist_name = playlist.get("name", "")
        if not playlist_name.startswith(options.playlist_prefix):
            continue

        save_playlist_in_db(playlist)
        # list_tracks_for_playlist(playlist)


def parse_arguments(arguments: [str], namespace: argparse.Namespace=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.set_defaults(command=lambda _: parser.print_usage())

    parser.add_argument("--cache-db", action="store", type=str,
                        dest="cache_url", default=DEFAULT_CACHE_FILE,
                        metavar="FILE", help="The local sqlite3-db used for caching.")
    # parser.add_argument("--log-level", action="store_const",
    #                     dest="log_level", default=logging.INFO,
    #                     metavar="LEVEL")
    parser.add_argument("--spotify-file", action="store", type=str,
                        dest="spotify_path", default=DEFAULT_SPOTIFY_APP_FILE,
                        metavar="FILE", help="The file to use for storing secret app key.")
    parser.add_argument("--token-file", action="store", type=str,
                        dest="token_path", default=DEFAULT_TOKEN_FILE,
                        metavar="FILE", help="The file to use for storing token information.")

    parser.add_argument("--playlist-prefix", action="store", type=str,
                        dest="playlist_prefix", metavar="PREFIX", default="SPOTIFYTAG ",
                        help="The prefix to use on playlists in Spotify.")

    subparsers = parser.add_subparsers(title="Subcommands")

    # Songs ###################################################################
    song_parser = subparsers.add_parser("songs", help="Manage songs")
    song_parser.set_defaults(command=lambda _: song_parser.print_usage())
    song_subparsers = song_parser.add_subparsers(title="Song management commands")

    song_list_parser = song_subparsers.add_parser("list", help="List current songs in local cache.")

    # Tokens ##################################################################
    token_parser = subparsers.add_parser("token", help="Handle authentication tokens")
    token_parser.set_defaults(command=lambda _: token_parser.print_usage())
    token_subparsers = token_parser.add_subparsers(title="Token management commands")

    token_request_parser = token_subparsers.add_parser("request", help="Request new token, both access- and refresh-token.")
    token_request_parser.set_defaults(command=request_token_command)
    token_request_parser.add_argument("--port",
                                      action="store", type=int, dest="redirect_server_port", metavar="PORT",
                                      default=DEFAULT_REDIRECT_SERVER_PORT,
                                      help=("Server port to use for the local redirect server."
                                            " Default is %d." % DEFAULT_REDIRECT_SERVER_PORT))

    token_refresh_parser = token_subparsers.add_parser("refresh", help="Refresh access-token using existing refresh-token")
    token_refresh_parser.set_defaults(command=refresh_token_command)

    token_validation_parser = token_subparsers.add_parser("validate", help="Check if the current token is valid")
    token_validation_parser.set_defaults(command=local_token_validation_command)

    # Tags ####################################################################
    tag_parser = subparsers.add_parser("tags", help="Manage tags")
    tag_parser.set_defaults(command=lambda _: tag_parser.print_usage())
    tag_subparsers = tag_parser.add_subparsers(title="Tag management commands")

    tag_list_parser = tag_subparsers.add_parser("list", help="List current tags in local cache.")

    tag_pull_parser = tag_subparsers.add_parser("pull", help="Pull current tags from Spotify.")
    tag_pull_parser.set_defaults(command=pull_tags_command)

    tag_push_parser = tag_subparsers.add_parser("push", help="Push current tags to Spotify.")

    # Playlists ###############################################################
    playlist_parser = subparsers.add_parser("playlists", help="Manage playlists")
    playlist_parser.set_defaults(command=lambda _: playlist_parser.print_usage())
    playlist_subparsers = playlist_parser.add_subparsers(title="Playlist commands")

    playlist_create_parser = playlist_subparsers.add_parser("create", help="Create a new (smart) playlist.")
    playlist_create_parser.set_defaults(command=lambda _: playlist_create_parser.print_usage())

    options = parser.parse_args(arguments, namespace=namespace)

    return options


if __name__ == "__main__":
    parse_arguments(sys.argv[1:], namespace=OPTIONS)

    logging.basicConfig(level=logging.DEBUG)

    OPTIONS.spotify_data = parse_json_from_file(OPTIONS.spotify_path)
    OPTIONS.token_data = parse_token_data_from_file(OPTIONS.token_path)

    OPTIONS.command(OPTIONS)
