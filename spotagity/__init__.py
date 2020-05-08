#!/usr/bin/env python3
# pylint: disable=missing-docstring

import argparse
import base64
from datetime import datetime, timedelta, tzinfo
import http.server
import json
import logging
import sys
from typing import Iterator, Tuple, Dict
import urllib.error
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    yaml = None

DESCRIPTION = """ This is more or less just a client for the Spotify web API with
                  some local caching and filters. I personally use it to create
                  tagging functionality by storing them as playlists.
              """

DEFAULT_REDIRECT_SERVER_PORT = 8000
REDIRECT_TO_ADDRESS = "https://accounts.spotify.com/authorize"
NEEDED_SCOPES = [
    "playlist-read-private",
]

DEFAULT_CACHE_FILE = "cache.db"
DEFAULT_SPOTIFY_APP_FILE = "spotify_app.json"
DEFAULT_TOKEN_FILE = "access_token.json"

# Serializing #################################################################

SERIALIZERS = {
    "json": json.dump,
}
if yaml:
    SERIALIZERS["yaml"] = yaml.dump
else:
    def stupid_yaml_serializer(data, output_file, level=0, indent_first=True):
        if isinstance(data, list):
            for item in data:
                if indent_first:
                    output_file.write("  " * level)
                output_file.write("- ")
                stupid_yaml_serializer(item, output_file,
                                       level=level + 1, indent_first=False)
                indent_first |= True
        elif isinstance(data, dict):
            for key, value in data.items():
                if indent_first:
                    output_file.write("  " * level)
                output_file.write(key)
                output_file.write(":")
                if isinstance(value, (list, dict)):
                    output_file.write("\n")
                    stupid_yaml_serializer(value, output_file,
                                           level + 1, indent_first=True)
                else:
                    output_file.write(" ")
                    stupid_yaml_serializer(value, output_file,
                                           level + 1, indent_first=False)
                indent_first |= True
        else:
            if indent_first:
                output_file.write("  " * level)
            json.dump(data, output_file)
            output_file.write("\n")
    SERIALIZERS["yaml"] = stupid_yaml_serializer

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

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


logger = logging.getLogger("spotagify")

# Stuff #######################################################################


class StoreDictValue(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, choices=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        if choices is None:
            raise ValueError("choices is needed")

        self.value_mapping = choices
        choices = choices.keys()

        super(StoreDictValue, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, self.value_mapping[values])

# HTTP ########################################################################
http_logger = logging.getLogger("spotagify.http")

def request(method, url, params=None, data=None, headers=None, raw_response=False):
    post_data = urllib.parse.urlencode(data).encode() if data is not None else None
    query_string = urllib.parse.urlencode(params) if params is not None else None
    headers = headers or {}

    url_string = "%s?%s" % (url, query_string) if query_string else url

    http_logger.debug("%s %s q=%s b=%s", method, url, params, data)
    for key, value in headers.items():
        http_logger.debug("%16s: %s", key, value)

    prepared_request = urllib.request.Request(url_string, data=post_data, headers=headers, method=method)
    response_data = {}

    if raw_response:
        return urllib.request.urlopen(prepared_request)

    try:
        response = urllib.request.urlopen(prepared_request)
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


def iterate_spotify_endpoint(endpoint: str, limit: int = None, params: Dict[str, str] = None,
                             options: argparse.Namespace = OPTIONS) -> Iterator[Dict]:
    headers = {"Authorization": "%(token_type)s %(access_token)s" % options.token_data}

    total_number = 2**63 - 1  # Very high number, will be corrected after fetch
    current_item = 0

    while current_item < total_number:
        query = {}
        if params:
            query.update(params)

        query["offset"] = current_item

        if limit is not None:
            query["limit"] = limit

        response_data = get(endpoint, params=query, headers=headers)

        total_number = response_data.get("total", 0)

        for item_data in response_data.get("items", []):
            yield item_data
            current_item += 1


# Authentication ##############################################################

def request_code(client_id: str, redirect_server_port: int) -> str:
    global _code

    class RedirectRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # pylint: disable=invalid-name
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
        def do_GET(self):  # pylint: disable=invalid-name
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


def refresh_token(refresh_token: str, client_id: str, client_secret: str) -> Dict:
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


# Playlists ###################################################################

def list_playlists() -> Iterator[Dict]:
    """ Return iterator over the current user's playlists. """
    endpoint = "https://api.spotify.com/v1/me/playlists"
    params = {
        "fields": "total,items(id,name,snapshot_id,tracks,href)"
    }

    return iterate_spotify_endpoint(endpoint, params=params)


def list_tracks_for_playlist(playlist: Dict) -> Iterator[Dict]:
    """ Return iterator over the tracks for a specific playlist. """
    tracks_url = playlist.get("tracks", {}).get("href")

    params = {
        # Limiting the data
        # "fields": "total,items(track(id,album(id,artists(id,name),name),artists(id,name),name,popularity,duration_ms))",
        "fields": "total,items.track(id,name)",
    }

    return iterate_spotify_endpoint(tracks_url, params=params)


###############################################################################

def parse_json_from_file(filename: str) -> Dict:
    data = {}
    try:
        with open(filename, "r") as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        pass

    return data


def parse_token_data_from_file(filename: str) -> Dict:
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

    logger.info("Token requested successfully")


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

    logger.info("Token refreshed successfully")


def list_playlists_command(options: argparse.Namespace) -> None:
    options.output_serializer(list(list_playlists()), sys.stdout)


def list_tags_command(options: argparse.Namespace) -> None:
    """ List playlists matching the tag pattern from the DB. """
    sql = ("SELECT name, id, snapshot_id FROM playlists WHERE name LIKE '%s%%';" %
           options.playlist_prefix)
    data = [{"id": id, "name": name[len(options.playlist_prefix):], "snapshot_id": snapshot_id}
            for name, id, snapshot_id in db_execute(sql)]
    options.output_serializer(data, sys.stdout)


def pull_tags_command(options: argparse.Namespace) -> None:
    """ Fetch tag-playlists from spotify and store them in DB. """
    def is_tag_playlist(playlist):
        return playlist.get("name", "").startswith(options.playlist_prefix)

    sql = "SELECT id, snapshot_id FROM playlists;"
    playlist_snapshots = {playlist_id: snapshot_id
                          for playlist_id, snapshot_id in db_execute(sql)}

    artists = dict()

    for playlist in filter(is_tag_playlist, list_playlists()):
        playlist_id = playlist["id"]
        snapshot_id = playlist["snapshot_id"]

        if playlist_snapshots.get(playlist_id) == snapshot_id:
            continue

        save_playlist_in_db(playlist)
        print("--- %s" % playlist.get("name"))

        for entry in list_tracks_for_playlist(playlist):
            print(entry.get("track", {}).get("name"))

            track = entry["track"]

            save_track_in_db(track)

            add_track_to_playlist(playlist=playlist, track=track)

            #     album = track.get("album")
            #     albums.append(album)

            artists.update({track_artist.get("id"): track_artist
                            for track_artist in track.get("artists", [])})


def list_tracks_command(options: argparse.Namespace) -> None:
    sql = "SELECT id, name FROM tracks;"
    data = [{"id": id, "name": name}
            for id, name in db_execute(sql)]
    options.output_serializer(data, sys.stdout)



def parse_arguments(arguments: [str], namespace: argparse.Namespace=None) -> argparse.Namespace:
    output_parser = argparse.ArgumentParser(add_help=False)

    def output_type(serializer_name):
        return SERIALIZERS[serializer_name]
    output_parser.add_argument("-o", "--output", action="store",  # choices=SERIALIZERS,
                               metavar="FORMAT", dest="output_serializer", type=output_type,
                               default="json", help="The output format to use.")
    loglevel_parser = argparse.ArgumentParser(add_help=False)
    loglevel_parser.add_argument("--log-level", action=StoreDictValue, choices=LOG_LEVELS,
                                 dest="log_level", default=logging.INFO,
                                 metavar="LEVEL", help="The logging level to use.")

    parser = argparse.ArgumentParser(parents=[loglevel_parser], description=DESCRIPTION)
    parser.set_defaults(command=lambda _: parser.print_usage())

    parser.add_argument("--cache-db", action="store", type=str,
                        dest="cache_url", default=DEFAULT_CACHE_FILE,
                        metavar="FILE", help="The local sqlite3-db used for caching.")
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

    # Tracks ###################################################################
    track_parser = subparsers.add_parser("tracks", help="Manage tracks")
    track_parser.set_defaults(command=lambda _: track_parser.print_usage())
    track_subparsers = track_parser.add_subparsers(title="Track management commands")

    track_list_parser = track_subparsers.add_parser("list", help="List current tracks in local cache.",
                                                    parents=[output_parser])
    track_list_parser.set_defaults(command=list_tracks_command)

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

    tag_list_parser = tag_subparsers.add_parser("list", help="List current tags in local cache.",
                                                parents=[output_parser])
    tag_list_parser.set_defaults(command=list_tags_command)

    tag_pull_parser = tag_subparsers.add_parser("pull", help="Pull current tags from Spotify.")
    tag_pull_parser.set_defaults(command=pull_tags_command)

    tag_push_parser = tag_subparsers.add_parser("push", help="Push current tags to Spotify.")

    # Playlists ###############################################################
    playlist_parser = subparsers.add_parser("playlists", help="Manage playlists")
    playlist_parser.set_defaults(command=lambda _: playlist_parser.print_usage())
    playlist_subparsers = playlist_parser.add_subparsers(title="Playlist commands")

    playlist_create_parser = playlist_subparsers.add_parser("create", help="Create a new (smart) playlist.")
    playlist_create_parser.set_defaults(command=lambda _: playlist_create_parser.print_usage())

    playlist_list_parser = playlist_subparsers.add_parser("list", help="List all playlists.", parents=[output_parser])
    playlist_list_parser.set_defaults(command=list_playlists_command)

    options = parser.parse_args(arguments, namespace=namespace)

    return options


if __name__ == "__main__":
    parse_arguments(sys.argv[1:], namespace=OPTIONS)

    logging.basicConfig(level=OPTIONS.log_level)

    OPTIONS.spotify_data = parse_json_from_file(OPTIONS.spotify_path)
    OPTIONS.token_data = parse_token_data_from_file(OPTIONS.token_path)

    OPTIONS.command(OPTIONS)
