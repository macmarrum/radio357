#!/usr/bin/python3
# macmarrum357 – an alternative CLI player for Radio357 patrons
# Copyright (C) 2024  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from requests import codes

__version__ = '2024.07.07'

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

STREAM = 'http://stream.radio357.pl'

USER_AGENT = f"macmarrum357/{__version__}"
EMAIL = 'email'
PASSWORD = 'password'
R357_PID = 'r357_pid'
R357_PID_EXPIRES = 'r357_pid_expires'
ACCESS_TOKEN = 'accessToken'
TOKEN = 'token'
TOKEN_DATE = 'token_date'
token_validity_delta = timedelta(days=30)
MPV_COMMAND = 'mpv_command'
MPV_OPTIONS = 'mpv_options'
is_debug = os.environ.get('DEBUG') == '1'


def info(*args, **kwargs):
    print('::', *args, **kwargs)


def debug(*args, **kwargs):
    if is_debug:
        print('>>', *args, **kwargs)


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
        debug(macmarrum357_json_path.name, macmarrum357)

email = macmarrum357.get(EMAIL)
password = macmarrum357.get(PASSWORD)
assert email and password, f"{macmarrum357_json_path} is missing email and/or password values"

r357_pid = macmarrum357.get(R357_PID)
r357_pid_expires = macmarrum357.get(R357_PID_EXPIRES)
token = macmarrum357.get(TOKEN)
token_date = macmarrum357.get(TOKEN_DATE)
if token_date:
    token_max_date = datetime.fromisoformat(token_date) + token_validity_delta
now = datetime.now(timezone.utc).astimezone()

is_to_dump_json = False
if not r357_pid or not r357_pid_expires or time.time() > r357_pid_expires:
    r357_pid = r357_pid_expires = None
    is_to_dump_json = True
    # get a new r357_pid
    url = 'https://checkout.radio357.pl/user/init/'
    info('GET', url)
    resp = requests.get(url)
    status_code = resp.status_code
    info(status_code)
    assert status_code == codes.ok, resp.text
    for cookie in iter(resp.cookies):
        debug('Cookie', [cookie.name, cookie.value, cookie.expires, cookie.domain, cookie.path])
        if cookie.name == R357_PID:
            info('Cookie', [cookie.name, cookie.value, cookie.expires, cookie.domain, cookie.path])
            r357_pid = cookie.value
            macmarrum357[R357_PID] = r357_pid
            r357_pid_expires = cookie.expires
            macmarrum357[R357_PID_EXPIRES] = r357_pid_expires
            break

if not token or not token_date or now > token_max_date:
    token = token_date = None
    is_to_dump_json = True
    # get a new token
    url = 'https://auth.r357.eu/api/auth/login'
    credentials = {EMAIL: email, PASSWORD: password}
    creds_with_hidden_password = credentials.copy()
    creds_with_hidden_password[PASSWORD] = '*' * len(credentials[PASSWORD])
    info('POST', url, f"json={creds_with_hidden_password}")
    resp = requests.post(url, json=credentials)
    status_code = resp.status_code
    assert status_code == codes.ok, resp.text
    d = resp.json()
    debug(status_code, d)
    token = d[ACCESS_TOKEN]
    info(ACCESS_TOKEN, token)
    macmarrum357[TOKEN] = token
    macmarrum357[TOKEN_DATE] = now.isoformat()

if is_to_dump_json:
    debug(macmarrum357_json_path, macmarrum357)
    with macmarrum357_json_path.open('w') as fo:
        json.dump(macmarrum357, fo, indent=2)

mpv = macmarrum357.get(MPV_COMMAND, 'mpv')
mpv_args = macmarrum357.get(MPV_OPTIONS, [])
args = [Path(mpv).name,
        STREAM,
        f"--user-agent={USER_AGENT}",
        f"--http-header-fields='Cookie: {TOKEN}={token}; {R357_PID}={r357_pid}'",
        # add any args specified in macmarrum357.json
        *mpv_args,
        # add any args passed on the command line
        *sys.argv[1:]
        ]
debug(mpv, args)
try:
    os.execvp(mpv, args)
except FileNotFoundError as e:
    print(f"** 'mpv_path' might be missing or incorrect in {macmarrum357_json_path}")
    raise
