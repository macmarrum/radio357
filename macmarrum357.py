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

me = Path(__file__)

__version__ = '2024.07.12'

logging.basicConfig()
macmarrum_log = logging.getLogger(me.stem)
if os.environ.get('MACMARRUM357_DEBUG') == '1':
    macmarrum_log.setLevel(logging.DEBUG)
    requests_log = logging.getLogger("urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True
    # Caution: this will log all request headers and data, and response headers (but no data)
    http.client.HTTPConnection.debuglevel = 1
    # http.client doesn't use logging, only print
    http_client_log = logging.getLogger('http.client')
    http.client.print = lambda *args: http_client_log.debug(' '.join(args))
    http_client_log.setLevel(logging.DEBUG)
else:
    macmarrum_log.setLevel(logging.INFO)


def get_appdata() -> Path:
    if os.name == 'nt':
        return Path(os.environ['APPDATA'])
    elif os.name == 'posix':
        return Path(os.environ.get('XDG_CONFIG_HOME', '~/.config')).expanduser()
    else:
        raise RuntimeError(f"unknown os.name: {os.name}")


def sleep_if_requested():
    sleep_sec = 0
    if '--sleep' in sys.argv:
        k = None
        for i, a in enumerate(sys.argv):
            if a == '--sleep':
                k = i
                break
        sleep_sec = float(sys.argv[k + 1])
        # remove --sleep SECONDS
        del sys.argv[k + 1]
        del sys.argv[k]
    if sleep_sec:
        macmarrum_log.info(f"sleeping for {sleep_sec} seconds")
        time.sleep(sleep_sec)


class c:
    EMAIL = 'email'
    PASSWORD = 'password'
    USER_AGENT = 'User-Agent'
    COOKIE = 'Cookie'
    R357_PID = 'r357_pid'
    R357_PID_EXPIRES = 'r357_pid_expires'
    R357_PID_EXPIRES_ = 'r357_pid_expires_'
    REFRESH_TOKEN = 'refresh_token'
    REFRESH_TOKEN_EXPIRES = 'refresh_token_expires'
    ACCESS_TOKEN = 'accessToken'
    REFRESHTOKEN = 'refreshToken'
    TOKEN = 'token'
    TOKEN_CREATED = 'token_created'
    TOKEN_EXPIRES = 'token_expires'
    MPV_COMMAND = 'mpv_command'
    MPV_OPTIONS = 'mpv_options'


class Macmarrum357:
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
    USER_AGENT = 'macmarrum/357'
    TOKEN_VALIDITY_DELTA = timedelta(minutes=60)
    macmarrum357_json_path = get_appdata() / 'macmarrum357.json'

    def __init__(self):
        self.conf = {}
        self.load_config()
        self.session = requests.Session()

    def load_config(self):
        if not self.macmarrum357_json_path.exists():
            with self.macmarrum357_json_path.open('w') as fo:
                conf = {c.EMAIL: '', c.PASSWORD: ''}
                if os.name == 'nt':
                    conf |= {c.MPV_COMMAND: 'mpv', c.MPV_OPTIONS: ['--force-window=immediate']}
                json.dump(conf, fo, indent=2)
        else:
            with self.macmarrum357_json_path.open('r') as fi:
                conf = json.load(fi)
                macmarrum_log.debug(f"READ {self.macmarrum357_json_path.name} {conf}")

        assert conf.get(c.EMAIL) and conf.get(c.PASSWORD), f"{self.macmarrum357_json_path} is missing email and/or password values"
        self.conf = conf

    def login_and_update_tokens_and_dump_json(self):
        macmarrum_log.debug('LOGIN to get new tokens')
        url = 'https://auth.r357.eu/api/auth/login'
        credentials = {c.EMAIL: self.conf[c.EMAIL], c.PASSWORD: self.conf[c.PASSWORD]}
        creds_with_hidden_password = credentials.copy()
        creds_with_hidden_password[c.PASSWORD] = '*' * len(credentials[c.PASSWORD])
        headers = {c.USER_AGENT: self.USER_AGENT}
        resp = self.session.post(url, headers=headers, json=credentials)
        status_code = resp.status_code
        assert status_code == codes.ok, f"{status_code} {resp.text}"
        self.update_tokens_from_resp(resp)
        self.dump_json()

    def update_tokens_from_resp(self, resp):
        macmarrum_log.debug(f"{resp.status_code} {resp.text}")
        d = resp.json()
        self.conf[c.TOKEN] = d[c.ACCESS_TOKEN]
        self.conf[c.TOKEN_CREATED] = datetime.now(timezone.utc).astimezone().replace(microsecond=0).isoformat()
        self.conf[c.REFRESH_TOKEN] = d[c.REFRESHTOKEN]

    def dump_json(self):
        macmarrum_log.debug(f"WRITE {self.macmarrum357_json_path.name} {self.conf}")
        with self.macmarrum357_json_path.open('w') as fo:
            json.dump(self.conf, fo, indent=2)

    def run(self):
        # ensure r357_pid
        r357_pid = self.conf.get(c.R357_PID)
        r357_pid_expires = self.conf.get(c.R357_PID_EXPIRES)
        if not r357_pid or not r357_pid_expires or time.time() > r357_pid_expires:
            self.init_r357()
            if self.conf[c.R357_PID] != r357_pid or self.conf[c.R357_PID_EXPIRES] != r357_pid_expires:
                self.dump_json()
        # query account to see if the token works
        resp = self.query_account()
        if resp.status_code == codes.unauthorized:
            refresh_token = self.conf.get(c.REFRESH_TOKEN)
            # try to refresh the token before falling back to login
            if refresh_token:
                resp = self.refresh_token()
                if resp.status_code == codes.ok:
                    self.update_tokens_from_resp(resp)
                    self.dump_json()
                elif resp.status_code == codes.unauthorized:
                    macmarrum_log.debug(f"{resp.status_code} {resp.text}")
                    self.login_and_update_tokens_and_dump_json()
                else:
                    resp.raise_for_status()
            else:
                self.login_and_update_tokens_and_dump_json()
            # query account to see if the new token works
            resp = self.query_account()
            assert resp.status_code == codes.ok, f"{resp.status_code} {resp.text}"
        else:
            # some other error (unexpected)
            resp.raise_for_status()
        sleep_if_requested()
        self.run_mpv()

    def init_r357(self):
        macmarrum_log.debug('INIT r357_pid')
        url = 'https://checkout.radio357.pl/user/init/'
        resp = self.session.get(url, headers={c.USER_AGENT: self.USER_AGENT})
        assert resp.status_code == codes.ok, f"{resp.status_code} {resp.text}"
        r357_pid = None
        for cookie in iter(resp.cookies):
            macmarrum_log.debug(f"{c.COOKIE} {[cookie.name, cookie.value, cookie.expires, cookie.domain, cookie.path]}")
            if cookie.name == c.R357_PID:
                r357_pid = cookie.value
                self.conf[c.R357_PID] = cookie.value
                self.conf[c.R357_PID_EXPIRES] = cookie.expires
                self.conf[c.R357_PID_EXPIRES_] = datetime.fromtimestamp(cookie.expires).astimezone().isoformat()
                break
        assert r357_pid, f"{c.R357_PID} is missing. This is unexpected."

    def query_account(self):
        # This is what the web app usually does, before playing the live stream
        macmarrum_log.debug('QUERY account')
        url = 'https://auth.r357.eu/api/account'
        token = self.conf.get(c.TOKEN)
        headers = {c.USER_AGENT: self.USER_AGENT, 'Authorization': f"Bearer {token}"}
        return self.session.get(url, headers=headers)

    def refresh_token(self):
        '''
        Based on https://radio357.pl/wp-content/plugins/r357api/public/r357api.js?_v=1720644011&ver=6.5.5
      getUser: (b, a = !1) => {
        d.call({
          method: 'GET',
          endpoint: p.api.uriAuth + '/account',
          auth: !0,
          callback: c => {
            let e = 'anonymous';
            if (200 == c.status) 'undefined' != typeof c.response &&
            'undefined' != typeof c.response.id &&
            (
              e = 'user',
              'undefined' != typeof c.response.patronIdHash &&
              10 < c.response.patronIdHash.length &&
              (e = 'patron')
            );
             else if (401 == c.status) {
              const g = d.readToken('refresh_token');
              if (g) {
                d.call({
                  method: 'POST',
                  endpoint: p.api.uriAuth + '/auth/refresh',
                  accept: 'application/json',
                  contentType: 'application/json',
                  payload: JSON.stringify({
                    refreshToken: g
                  }),
        ...
      readToken: (b = 'token') => {
        let a = (
          document.cookie.match(new RegExp('(^|\\s+|;)' + b + '=([^;]+)', 'i')) ||
          [
            null
          ]
        ).pop();
        a &&
        (a = decodeURIComponent(a));
        'token' == b &&
        (d.token = a);
        - 1 < window.location.href.indexOf('test=logowanie') &&
        d.debugLog({
          cookie: document.cookie,
          type: b,
          token: a,
          user: l
        });
        return a
      },
        '''
        macmarrum_log.debug('REFRESH token')
        url = 'https://auth.r357.eu/api/refresh'
        refresh_token = self.conf[c.REFRESH_TOKEN]
        return self.session.post(url, headers={c.USER_AGENT: self.USER_AGENT}, json={c.REFRESHTOKEN: refresh_token})

    def run_mpv(self):
        mpv = self.conf.get(c.MPV_COMMAND, 'mpv')
        mpv_args = self.conf.get(c.MPV_OPTIONS, [])
        args = [Path(mpv).name,
                self.STREAM,
                f"--user-agent={self.USER_AGENT}",
                f"--http-header-fields='{c.COOKIE}: {self.mk_cookie()}'",
                # add any args specified in macmarrum357.json
                *mpv_args,
                # add any args passed on the command line
                *sys.argv[1:]
                ]
        macmarrum_log.debug(f"{mpv} {args}")
        try:
            os.execvp(mpv, args)
        except FileNotFoundError as e:
            print(f"** 'mpv_path' might be missing or incorrect in {self.macmarrum357_json_path}")
            raise

    def mk_cookie(self):
        token = self.conf[c.TOKEN]
        token_expires = self.calc_token_expires()
        refresh_token = self.conf[c.REFRESH_TOKEN]
        r357_pid = self.conf[c.R357_PID]
        return (f"{c.TOKEN}={token}; {c.TOKEN_EXPIRES}={token_expires}; "
                f"{c.REFRESH_TOKEN}={refresh_token}; {c.REFRESH_TOKEN_EXPIRES}={token_expires}; "
                f"{c.R357_PID}={r357_pid}")

    def calc_token_expires(self) -> int:
        token_created = self.conf[c.TOKEN_CREATED]
        expiry_dt = datetime.fromisoformat(token_created) + self.TOKEN_VALIDITY_DELTA
        return int(expiry_dt.timestamp()) * 1000


if __name__ == '__main__':
    Macmarrum357().run()
