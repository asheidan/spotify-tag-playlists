import sqlite3

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
    if args:
        db_logger.debug(args)

    cursor.execute(sql, args, **kwargs)

    return cursor


def create_tables_in_database(cursor: sqlite3.Cursor=None) -> None:
    cursor = cursor or db_cursor()

    db_execute("""SELECT name FROM sqlite_master WHERE type=?;""", "table", cursor=cursor)
    existing_tables = frozenset(row[0] for row in cursor)

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

    if "tracks" not in existing_tables:
        db_execute("""CREATE TABLE tracks (
                              id TEXT PRIMARY KEY NOT NULL,
                              name TEXT);""",
                   cursor=cursor)

    if "track_artists" not in existing_tables:
        db_execute("""CREATE TABLE track_artists (
                              track_id TEXT, artist_id TEXT,
                              FOREIGN KEY (track_id) REFERENCES tracks(id),
                              FOREIGN KEY (artist_id) REFERENCES artists(id));""",
                   cursor=cursor)

    if "playlist_tracks" not in existing_tables:
        db_execute("""CREATE TABLE playlist_tracks (
                              playlist_id TEXT, track_id TEXT,
                              FOREIGN KEY (playlist_id) REFERENCES playlists(id),
                              FOREIGN KEY (track_id) REFERENCES tracks(id));""")

    cursor.connection.commit()


def save_playlist_in_db(playlist: Dict, cursor: sqlite3.Cursor=None) -> None:
    db_logger.info("Saving playlist: %(name)s" % playlist)

    cursor = db_execute("INSERT OR REPLACE INTO playlists(id, name, snapshot_id, href) VALUES(?, ?, ?, ?);",
                        *playlist_to_db(playlist), cursor=cursor)

    cursor.connection.commit()


def save_track_in_db(track: Dict, cursor: sqlite3.Cursor=None) -> None:
    db_logger.info("Saving track: %(name)s" % track)

    cursor = db_execute("INSERT OR REPLACE INTO tracks(id, name) VALUES(?, ?);",
                        *track_to_db(track), cursor=cursor)

    cursor.connection.commit()


def add_track_to_playlist(playlist=None, track=None, cursor: sqlite3.Cursor=None) -> None:
    db_logger.info("Adding track to playlist: %s, %s" , track.get("name"), playlist.get("name"))

    cursor = db_execute("INSERT OR REPLACE INTO playlist_tracks(playlist_id, track_id) VALUES(?, ?);",
                        playlist["id"], track["id"], cursor=cursor)

    cursor.connection.commit()


def playlist_to_db(playlist: Dict) -> Tuple:
    return playlist["id"], playlist["name"], playlist["snapshot_id"], playlist["href"]


def track_to_db(track: Dict) -> Tuple:
    return track["id"], track["name"]



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


def parse_arguments():
