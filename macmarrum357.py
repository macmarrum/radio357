#!/usr/bin/python3
# macmarrum357 – an alternative CLI player for Radio357 patrons
# Copyright (C) 2024  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import http.client
import json
import logging
import os
import pickle
import sys
import time
from datetime import datetime, timedelta
from http.cookiejar import MozillaCookieJar, CookieJar, Cookie
from pathlib import Path

import requests
from requests import codes
from requests.cookies import RequestsCookieJar

me = Path(__file__)

__version__ = '2024.07.13'

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


def mk_mozilla_cookies_csv_list(cookiejar: RequestsCookieJar | CookieJar, sep: str = ' ', end: str = None):
    lst = []
    for cookie in cookiejar:
        expires = datetime.fromtimestamp(cookie.expires).astimezone().isoformat()
        lst.append(f"{cookie.domain}{sep}{cookie.domain_initial_dot}{sep}{cookie.path}{sep}{cookie.secure}{sep}{expires}{sep}{cookie.name}{sep}{cookie.value}")
    if end is not None:
        return end.join(lst)
    else:
        return lst


class c:
    EMAIL = 'email'
    PASSWORD = 'password'
    USER_AGENT = 'User-Agent'
    R357_PID = 'r357_pid'
    REFRESH_TOKEN = 'refresh_token'
    REFRESH_TOKEN_EXPIRES = 'refresh_token_expires'
    ACCESS_TOKEN = 'accessToken'
    REFRESHTOKEN = 'refreshToken'
    TOKEN = 'token'
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

    Path to mpv and mpv options can be specified in the same file, e.g.
    "mpv_command": "c:\\Program Files\\mpv\\mpv.exe"
    "mpv_options": ["--force-window=immediate"]
    When mpv_command is missing, macmarrum357 looks for mpv in PATH.

    Sleeps for SECONDS before starting mpv, if `--sleep SECONDS` arguments are found in the command line.

    Passes all other command-line arguments to mpv, so that macmarrum357 can be used as a drop-in replacement for mpv,
    e.g. adding `--end=60:00 --mute=yes --stream-record=output.aac`
    will quietly record 60 minutes of the stream to output.aac
    """
    STREAM = 'https://stream.radio357.pl/'
    USER_AGENT = 'macmarrum/357'
    TOKEN_VALIDITY_DELTA = timedelta(minutes=60)
    macmarrum357_path = get_appdata() / 'macmarrum357'
    macmarrum357_path.mkdir(exist_ok=True)
    macmarrum357_json_path = macmarrum357_path / 'config.json'
    macmarrum357_cookies_pickle_path = macmarrum357_path / 'cookies.pickle'
    macmarrum357_cookies_txt_path = macmarrum357_path / 'cookies.txt'

    def __init__(self):
        self.conf = {}
        self.load_config()
        self.session = requests.Session()
        self.load_cookies()

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
                macmarrum_log.debug(f"LOAD {self.macmarrum357_json_path.name} {conf}")
        assert conf.get(c.EMAIL) and conf.get(c.PASSWORD), f"{self.macmarrum357_json_path} is missing email and/or password values"
        self.conf = conf

    def load_cookies(self):
        try:
            with self.macmarrum357_cookies_pickle_path.open('rb') as fi:
                cj: RequestsCookieJar = pickle.load(fi)
                for cookie_line in mk_mozilla_cookies_csv_list(cj):
                    macmarrum_log.debug(f"LOAD {self.macmarrum357_cookies_pickle_path.name} {cookie_line}")
                self.session.cookies.update(cj)
        except FileNotFoundError:
            pass

    def run(self):
        # ensure r357_pid
        r357_pid = self.get_cookie(c.R357_PID)
        if not r357_pid.value or r357_pid.is_expired():
            self.init_r357()
            r357_pid_new = self.get_cookie(c.R357_PID)
            if r357_pid_new.value != r357_pid.value or r357_pid_new.expires != r357_pid.expires:
                self.dump_cookies_pickle()
                self.save_cookies_txt()
        token = self.get_cookie(c.TOKEN)
        if token.value and not token.is_expired():
            # query account to see if the token works
            resp = self.query_account()
            if resp.status_code == codes.unauthorized:
                self.refresh_or_login_and_query_to_verify()
            else:
                # some other error (unexpected)
                resp.raise_for_status()
        else:
            self.refresh_or_login_and_query_to_verify()
        sleep_if_requested()
        self.run_mpv()

    def get_cookie(self, name):
        for cookie in self.session.cookies:
            if cookie.name == name:
                return cookie
        return Cookie(None, name, None, None, False, '', False, False,
                      '', False, False, None, False, None, None, {}, False)

    def init_r357(self):
        macmarrum_log.debug('INIT r357_pid')
        url = 'https://checkout.radio357.pl/user/init/'
        resp = self.session.get(url, headers={c.USER_AGENT: self.USER_AGENT})
        assert resp.status_code == codes.ok, f"{resp.status_code} {resp.text}"
        assert self.session.cookies.get(c.R357_PID), f"{c.R357_PID} is missing. This is unexpected."

    def dump_cookies_pickle(self):
        cj = self.session.cookies.copy()
        cj.clear_session_cookies()
        cj.clear_expired_cookies()
        for cookie_line in mk_mozilla_cookies_csv_list(cj):
            macmarrum_log.debug(f"WRITE {self.macmarrum357_cookies_pickle_path.name} {cookie_line}")
        with self.macmarrum357_cookies_pickle_path.open('wb') as fo:
            pickle.dump(cj, fo)

    def save_cookies_txt(self):
        mcj = MozillaCookieJar()
        for cookie in self.session.cookies:
            mcj.set_cookie(cookie)
        mcj.clear_session_cookies()
        mcj.clear_expired_cookies()
        for cookie_line in mk_mozilla_cookies_csv_list(mcj):
            macmarrum_log.debug(f"WRITE {self.macmarrum357_cookies_txt_path.name} {cookie_line}")
        mcj.save(self.macmarrum357_cookies_txt_path.as_posix())

    def query_account(self):
        # This is what the web app usually does, before playing the live stream
        macmarrum_log.debug('QUERY account')
        url = 'https://auth.r357.eu/api/account'
        token = self.session.cookies.get(c.TOKEN)
        headers = {c.USER_AGENT: self.USER_AGENT, 'Authorization': f"Bearer {token}"}
        return self.session.get(url, headers=headers)

    def refresh_or_login_and_query_to_verify(self):
        refresh_token = self.get_cookie(c.REFRESH_TOKEN)
        # try to refresh the token before falling back to login
        # TODO observe to decide whether to skip the refresh attempt when token's expired
        if refresh_token.value:
            resp = self.refresh_token()
            if resp.status_code == codes.ok:
                self.update_tokens_from_resp(resp)
                self.dump_cookies_pickle()
                self.save_cookies_txt()
            elif resp.status_code == codes.unauthorized:
                macmarrum_log.debug(f"{resp.status_code} {resp.text}")
                self.login_and_update_tokens_and_persist_cookies()
            else:
                # some other error (unexpected)
                resp.raise_for_status()
        else:
            self.login_and_update_tokens_and_persist_cookies()
        # query account to see if the new token works
        resp = self.query_account()
        assert resp.status_code == codes.ok, f"{resp.status_code} {resp.text}"

    def refresh_token(self):
        _ = '''
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
        refresh_token = self.session.cookies.get(c.REFRESH_TOKEN)
        return self.session.post(url, headers={c.USER_AGENT: self.USER_AGENT}, json={c.REFRESHTOKEN: refresh_token})

    def update_tokens_from_resp(self, resp):
        macmarrum_log.debug(f"{resp.status_code} {resp.text}")
        d = resp.json()
        expires = int((datetime.now().replace(microsecond=0) + self.TOKEN_VALIDITY_DELTA).timestamp())
        cookie = Cookie(0, c.TOKEN, d[c.ACCESS_TOKEN], None, False, '.radio357.pl', True, True,
                        '/', True, False, expires, False, None, None, {}, False)
        self.session.cookies.set_cookie(cookie)
        cookie = Cookie(0, c.TOKEN_EXPIRES, f"{expires}000", None, False, '.radio357.pl', True, True,
                        '/', True, False, expires, False, None, None, {}, False)
        self.session.cookies.set_cookie(cookie)
        cookie = Cookie(0, c.REFRESH_TOKEN, d[c.REFRESHTOKEN], None, False, '.radio357.pl', True, True,
                        '/', True, False, expires, False, None, None, {}, False)
        self.session.cookies.set_cookie(cookie)
        cookie = Cookie(0, c.REFRESH_TOKEN_EXPIRES, f"{expires}000", None, False, '.radio357.pl', True, True,
                        '/', True, False, expires, False, None, None, {}, False)
        self.session.cookies.set_cookie(cookie)

    def login_and_update_tokens_and_persist_cookies(self):
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
        self.dump_cookies_pickle()
        self.save_cookies_txt()

    def run_mpv(self):
        mpv = self.conf.get(c.MPV_COMMAND, 'mpv')
        mpv_args = self.conf.get(c.MPV_OPTIONS, [])
        args = [Path(mpv).name,
                self.STREAM,
                f"--user-agent={self.USER_AGENT}",
                '--cookies=yes',
                f"--cookies-file={self.macmarrum357_cookies_txt_path}",
                # add any args specified in macmarrum357.json
                *mpv_args,
                # add any args passed on the command line
                *sys.argv[1:]
                ]
        macmarrum_log.debug(f"{mpv} {args}")
        try:
            os.execvp(mpv, args)
        except FileNotFoundError:
            print(f"** 'mpv_path' might be missing or incorrect in {self.macmarrum357_json_path}")
            raise


if __name__ == '__main__':
    Macmarrum357().run()
