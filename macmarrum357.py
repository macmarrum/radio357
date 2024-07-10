#!/usr/bin/python3
# macmarrum357 – an alternative CLI player for Radio357 patrons
# Copyright (C) 2024  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import http.client
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from requests import codes

APP_NAME = 'macmarrum357'
__version__ = '2024.07.10'

"""
Plays the live stream of Radio 357, as a logged-in user, which skips the start-up announcement.

Logs in, gets cookies and uses them to play the stream with mpv.
Email and password for https://konto.radio357.pl must be specified in
- %APPDATA%/macmarrum357.json – on Windows
or
- ~/.config/macmarrum357.json – on Unix

Path to mpv and mpv_args can be specified in the same file, e.g.
"mpv_path": "c:\\Program Files\\mpv\\mpv.exe"
"mpv_args": ["--force-window=immediate"]
When mpv_path is missing, macmarrum357 looks for mpv in PATH.

Passes all command-line arguments to mpv, so that macmarrum357 can be used as a drop-in replacement for mpv,
e.g. adding `--end=60:00 --mute=yes --stream-record=output.aac`
will quietly record 60 minutes of the stream to output.aac
"""

STREAM = 'http://stream.radio357.pl/'

EMAIL = 'email'
PASSWORD = 'password'
USER_AGENT = 'User-Agent'
COOKIE = 'Cookie'
REFRESH_TOKEN = 'refresh_token'
REFRESH_TOKEN_EXPIRES = 'refresh_token_expires'
ACCESS_TOKEN = 'accessToken'
REFRESHTOKEN = 'refreshToken'
TOKEN = 'token'
TOKEN_DATE = 'token_date'
TOKEN_EXPIRES = 'token_expires'
token_validity_delta = timedelta(minutes=60)
MPV_COMMAND = 'mpv_command'
MPV_OPTIONS = 'mpv_options'
is_debug = os.environ.get('MACMARRUM357_DEBUG') == '1'

logging.basicConfig()
macmarrum_log = logging.getLogger(APP_NAME)
if is_debug:
    # https://docs.python-requests.org/en/latest/api/#api-changes
    logging.getLogger().setLevel(logging.DEBUG)
    # Caution: this will log all request headers and data, and response headers (but no data)
    http.client.HTTPConnection.debuglevel = 1
    # http.client doesn't use logging, only print
    http_client_log = logging.getLogger('http.client')
    http.client.print = lambda *args: http_client_log.debug(' '.join(args))
    requests_log = logging.getLogger("urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True
else:
    macmarrum_log.setLevel(logging.INFO)


def get_appdata() -> Path:
    if os.name == 'nt':
        return Path(os.environ['APPDATA'])
    elif os.name == 'posix':
        return Path(os.environ.get('XDG_CONFIG_HOME', '~/.config')).expanduser()
    else:
        raise RuntimeError(f"unknown os.name: {os.name}")


macmarrum357_json_path = get_appdata() / 'macmarrum357.json'

if not macmarrum357_json_path.exists():
    with macmarrum357_json_path.open('w') as fo:
        macmarrum357 = {EMAIL: '', PASSWORD: '', MPV_COMMAND: 'mpv', MPV_OPTIONS: ['--force-window=immediate']}
        json.dump(macmarrum357, fo, indent=2)
else:
    with macmarrum357_json_path.open('r') as fi:
        macmarrum357 = json.load(fi)
        macmarrum_log.debug(f"READ {macmarrum357_json_path.name} {macmarrum357}")

email = macmarrum357.get(EMAIL)
password = macmarrum357.get(PASSWORD)
assert email and password, f"{macmarrum357_json_path} is missing email and/or password values"


def calc_token_expires(token_created: str | datetime) -> int:
    if token_created:
        if isinstance(token_created, datetime):
            dt = token_created
        else:
            dt = datetime.fromisoformat(token_created) + token_validity_delta
        return int(dt.timestamp()) * 1000
    else:
        return 0


now = datetime.now(timezone.utc).astimezone()
token = macmarrum357.get(TOKEN)
token_date = macmarrum357.get(TOKEN_DATE)
refresh_token = macmarrum357.get(REFRESH_TOKEN)
token_expires = calc_token_expires(token_date or now)
user_agent = APP_NAME

is_to_dump_json = False
if not token or not token_date or time.time() > token_expires / 1000:
    macmarrum_log.debug('a new token needs to be requested')
    token = token_date = refresh_token = None
    is_to_dump_json = True
    # get a new token
    url = 'https://auth.r357.eu/api/auth/login'
    credentials = {EMAIL: email, PASSWORD: password}
    creds_with_hidden_password = credentials.copy()
    creds_with_hidden_password[PASSWORD] = '*' * len(credentials[PASSWORD])
    headers = {USER_AGENT: user_agent}
    resp = requests.post(url, headers=headers, json=credentials)
    status_code = resp.status_code
    assert status_code == codes.ok, f"{status_code} {resp.text}"
    d = resp.json()
    token = d[ACCESS_TOKEN]
    refresh_token = d[REFRESHTOKEN]
    macmarrum357[TOKEN] = token
    macmarrum357[TOKEN_DATE] = now.isoformat()
    macmarrum357[REFRESH_TOKEN] = refresh_token

if is_to_dump_json:
    macmarrum_log.debug(f"WRITE {macmarrum357_json_path.name} {macmarrum357}")
    with macmarrum357_json_path.open('w') as fo:
        json.dump(macmarrum357, fo, indent=2)

# This is what the web app usually does, before playing the live stream
url = 'https://auth.r357.eu/api/account'
headers = {USER_AGENT: user_agent, 'Authorization': f"Bearer {token}"}
resp = requests.get(url, headers=headers)
status_code = resp.status_code
assert status_code == codes.ok, f"{status_code} {resp.reason}"

sleep_sec = 0
if '--sleep' in sys.argv:
    k = None
    for i, a in enumerate(sys.argv):
        if a == '--sleep':
            k = i
            break
    sleep_sec = float(sys.argv[k + 1])
    # remove --sleep d
    del sys.argv[k + 1]
    del sys.argv[k]

if sleep_sec:
    macmarrum_log.info(f"sleeping for {sleep_sec} seconds")
    time.sleep(sleep_sec)


def mk_cookie():
    return f"{TOKEN}={token}; {TOKEN_EXPIRES}={token_expires}; {REFRESH_TOKEN}={refresh_token}; {REFRESH_TOKEN_EXPIRES}={token_expires}"


mpv = macmarrum357.get(MPV_COMMAND, 'mpv')
mpv_args = macmarrum357.get(MPV_OPTIONS, [])
args = [Path(mpv).name,
        STREAM,
        f"--user-agent={user_agent}",
        f"--http-header-fields='{COOKIE}: {mk_cookie()}'",
        # add any args specified in macmarrum357.json
        *mpv_args,
        # add any args passed on the command line
        *sys.argv[1:]
        ]
macmarrum_log.debug(f"{mpv} {args}")
try:
    os.execvp(mpv, args)
except FileNotFoundError as e:
    print(f"** 'mpv_path' might be missing or incorrect in {macmarrum357_json_path}")
    raise
