#!/usr/bin/python3
# macmarrum357 – an alternative CLI player for Radio357 patrons
# Copyright (C) 2024  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import http.client
import json
import logging
import os
import pickle
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from http.cookiejar import MozillaCookieJar, CookieJar, Cookie
from pathlib import Path
from threading import Thread
from time import sleep, time
from typing import Callable, Sequence

import requests
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
        sleep(sleep_sec)


def iter_mozilla_cookies_as_csv(cookiejar: RequestsCookieJar | CookieJar, sep: str = ' '):
    for cookie in cookiejar:
        yield mk_mozilla_cookie_csv(cookie, sep)


def mk_mozilla_cookie_csv(cookie: Cookie, sep: str = ' '):
    expires = datetime.fromtimestamp(cookie.expires).astimezone().isoformat()
    return f"{cookie.domain}{sep}{cookie.domain_initial_dot}{sep}{cookie.path}{sep}{cookie.secure}{sep}{expires}{sep}{cookie.name}{sep}{cookie.value}"


def mk_filename(start: datetime, end: datetime, duration: timedelta, file_num: int, count: int):
    return f"{start.strftime('%Y-%m-%d,%a_%H,%M')}.aac"


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

    Alternatively, `--record='{"output_dir": "/path/to/directory", "switch_file_at":"[6, 9, 12]"}'
    """
    STREAM = 'https://stream.radio357.pl/'
    USER_AGENT = 'macmarrum/357'
    TOKEN_VALIDITY_DELTA = timedelta(minutes=60)
    RECORD_CHUNK_SIZE = 4096
    macmarrum357_path = get_appdata() / 'macmarrum357'
    macmarrum357_path.mkdir(exist_ok=True)
    macmarrum357_json_path = macmarrum357_path / 'config.json'
    macmarrum357_cookies_pickle_path = macmarrum357_path / 'cookies.pickle'
    macmarrum357_cookies_txt_path = macmarrum357_path / 'cookies.txt'
    hours = list(range(0, 23))

    def __init__(self):
        self.conf = {}
        self.load_config()
        self.session = requests.Session()
        self.load_cookies()
        self.is_cookies_changed = False
        self.record_hour = None

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
        assert conf.get(c.EMAIL) and conf.get(
            c.PASSWORD), f"{self.macmarrum357_json_path} is missing email and/or password values"
        self.conf = conf

    def load_cookies(self):
        try:
            with self.macmarrum357_cookies_pickle_path.open('rb') as fi:
                cj: RequestsCookieJar = pickle.load(fi)
                for cookie_line in iter_mozilla_cookies_as_csv(cj):
                    macmarrum_log.debug(f"LOAD {self.macmarrum357_cookies_pickle_path.name} {cookie_line}")
                self.session.cookies.update(cj)
        except FileNotFoundError:
            pass

    def play(self):
        self.ensure_login_done()
        sleep_if_requested()
        self.run_mpv()

    def ensure_login_done(self):
        # ensure r357_pid
        r357_pid = self.get_cookie(c.R357_PID)
        if not r357_pid.value or r357_pid.is_expired():
            self.init_r357()
            r357_pid_new = self.get_cookie(c.R357_PID)
            if r357_pid_new.value != r357_pid.value or r357_pid_new.expires != r357_pid.expires:
                self.is_cookies_changed = True
        token = self.get_cookie(c.TOKEN)
        if token.value and not token.is_expired():
            # query account to see if the token works
            resp = self.query_account()
            if resp.status_code == 401:
                resp = self.refresh_or_login_and_query_to_verify()
                assert resp.status_code == 200, f"{resp.status_code} {resp.text}"
            else:
                # some other error (unexpected)
                resp.raise_for_status()
        else:
            resp = self.refresh_or_login_and_query_to_verify()
            assert resp.status_code == 200, f"{resp.status_code} {resp.text}"
        if self.is_cookies_changed:
            self.dump_cookies_pickle()
            self.save_cookies_txt()
            self.is_cookies_changed = False

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
        assert resp.status_code == 200, f"{resp.status_code} {resp.text}"
        assert self.session.cookies.get(c.R357_PID), f"{c.R357_PID} is missing. This is unexpected."

    def dump_cookies_pickle(self):
        cj = self.session.cookies.copy()
        cj.clear_session_cookies()
        cj.clear_expired_cookies()
        for cookie_line in iter_mozilla_cookies_as_csv(cj):
            macmarrum_log.debug(f"WRITE {self.macmarrum357_cookies_pickle_path.name} {cookie_line}")
        with self.macmarrum357_cookies_pickle_path.open('wb') as fo:
            pickle.dump(cj, fo)

    def save_cookies_txt(self):
        mcj = MozillaCookieJar()
        for cookie in self.session.cookies:
            mcj.set_cookie(cookie)
        mcj.clear_session_cookies()
        mcj.clear_expired_cookies()
        for cookie_line in iter_mozilla_cookies_as_csv(mcj):
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
        if refresh_token.value and not refresh_token.is_expired():
            resp = self.refresh_token()
            if resp.status_code == 200:
                self.update_and_persist_tokens_from_resp(resp)
            elif resp.status_code == 401:
                macmarrum_log.debug(f"{resp.status_code} {resp.text}")
                resp = self.login_and_update_tokens_and_persist_cookies()
                if resp.status_code == 200:
                    self.update_and_persist_tokens_from_resp(resp)
            else:
                # some other error (unexpected)
                resp.raise_for_status()
        else:
            resp = self.login_and_update_tokens_and_persist_cookies()
            if resp.status_code == 200:
                self.update_and_persist_tokens_from_resp(resp)
        # query account to see if the new token works
        return self.query_account()

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

    def update_and_persist_tokens_from_resp(self, resp):
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
        self.dump_cookies_pickle()
        self.save_cookies_txt()
        self.is_cookies_changed = False

    def login_and_update_tokens_and_persist_cookies(self):
        macmarrum_log.debug('LOGIN to get new tokens')
        url = 'https://auth.r357.eu/api/auth/login'
        credentials = {c.EMAIL: self.conf[c.EMAIL], c.PASSWORD: self.conf[c.PASSWORD]}
        headers = {c.USER_AGENT: self.USER_AGENT}
        return self.session.post(url, headers=headers, json=credentials)

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
        macmarrum_log.debug(f"RUN {mpv} {args}")
        try:
            os.execvp(mpv, args)
        except FileNotFoundError:
            print(f"** 'mpv_path' might be missing or incorrect in {self.macmarrum357_json_path}")
            raise

    def record(self, args_as_json: str):
        macmarrum_log.debug(f"{args_as_json=}")
        record_args = json.loads(args_as_json)
        macmarrum_log.debug(f"{record_args=}")
        self.start_recording(**record_args)

    def start_recording(self, output_dir: str | Path, filename: str | Callable = None,
                        switch_file_at: Sequence[str | int] = ('*',), count=None, player: str | Callable | None = None):
        """
        :param output_dir:
        :param filename:
        :param switch_file_at: a sequence of time spec 'HH:MM:SS', e.g. ('6:00', '9:00', '12:00'), the last one meaning exit
        :param count: number of hourly '*' files to be produced; None means from now till midnight
        :param player:
        :return:
        """
        if filename is None:
            filename = mk_filename
        switch_file_at_list = []
        is_every_hour_found = any(spec.startswith('*') for spec in switch_file_at)
        if is_every_hour_found:
            assert len(switch_file_at) == 1
            e = self.parse_switch_file_at_spec(switch_file_at[0], is_every_hour_found)
            switch_file_at_list.append(e)
            if count is None:
                count = 24 - datetime.now().hour
        else:
            for spec in switch_file_at:
                e = self.parse_switch_file_at_spec(spec, is_every_hour_found)
                switch_file_at_list.append(e)
            count = len(switch_file_at_list)

        def mk_switch_file_at_gen():
            if is_every_hour_found:
                h, m, s = switch_file_at_list[0]
                for i in range(1, count + 1):
                    if self.record_hour is None:
                        self.record_hour = datetime.now(timezone.utc).astimezone().hour
                    h = 0 if self.record_hour == 23 else self.record_hour + 1
                    self.record_hour = h
                    yield i, *self.calc_start_end_duration(h, m, s)
            else:
                for i, h, m, s in enumerate(switch_file_at_list, start=1):
                    yield i, *self.calc_start_end_duration(h, m, s)
            return None, None, None, None

        switch_file_at_gen = mk_switch_file_at_gen()

        def start_file_out():
            file_num, start, end, duration = next(switch_file_at_gen)
            if file_num is None:
                return None, None, None, None
            output_path = Path(output_dir) / filename(start=start, end=end, duration=duration, file_num=file_num,
                                                      count=count) if callable(filename) else filename
            macmarrum_log.info(f"RECORD {file_num}/{count} {duration} to {output_path}")
            if output_path.exists():
                macmarrum_log.warning(f"Writing to an existing file: {output_path}")
            return output_path, output_path.open('wb'), file_num, end

        def spawn_player_if_requested(path):
            if player is not None:
                if callable(player):
                    player(path)
                else:
                    if player == 'mpv_command':
                        mpv_command = self.conf.get(c.MPV_COMMAND, 'mpv')
                        mpv_options = self.conf.get(c.MPV_OPTIONS, [])
                        args = [mpv_command, *mpv_options, f"appending://{path}"]
                    else:
                        args = [player, str(path)]
                    macmarrum_log.info(f"SPAWN {args}")
                    return subprocess.Popen(args).pid

        self.ensure_login_done()
        file_path, fo, num, end_dt = start_file_out()
        resp = self.session.get(self.STREAM, headers={c.USER_AGENT: self.USER_AGENT}, stream=True)
        resp.raise_for_status()
        spawn_player_if_requested(file_path)
        self.run_periodic_token_refresh_thread()
        for chunk in resp.iter_content(chunk_size=self.RECORD_CHUNK_SIZE):
            fo.write(chunk)
            if end_dt and datetime.now(timezone.utc) >= end_dt:
                fo.close()
                file_path, fo, num, end_dt = start_file_out()
                if file_path is None:
                    break
                else:
                    spawn_player_if_requested(file_path)
        if not fo.closed:
            fo.close()

    @staticmethod
    def parse_switch_file_at_spec(switch_file_at_spec: str | int, is_every_hour_found: bool):
        hms = str(switch_file_at_spec).split(':')
        if len(hms) == 1:
            h = hms[0]
            m = 0
            s = 0
        elif len(hms) == 2:
            h, m = hms
            s = 0
        elif len(hms) == 3:
            h, m, s = hms
        else:
            raise ValueError(f"{hms} contains {len(hms)} parts - expected 1, 2 or 3")
        if is_every_hour_found:
            assert h == '*'
            h = None
        else:
            h = int(h)
        m = int(m)
        s = int(s)
        return h, m, s

    @staticmethod
    def calc_start_end_duration(h, m, s):
        start = datetime.now(timezone.utc).astimezone()
        end = start if h > start.hour else start + timedelta(days=1)
        end = end.replace(hour=h, minute=m, second=s, microsecond=0)
        duration = end - start
        return start, end, duration

    def run_periodic_token_refresh_thread(self):
        def periodic_token_refresh():
            macmarrum_log.debug('RUN periodic_token_refresh')
            expires = self.get_cookie(c.TOKEN).expires
            expires_with_margin = expires - 5
            while time() < expires_with_margin:
                sleep(5)
            attempt = 0
            while True:
                attempt += 1
                macmarrum_log.debug(f"periodic_token_refresh ATTEMPT {attempt}")
                resp = self.refresh_or_login_and_query_to_verify()
                if resp.status_code != 200:
                    macmarrum_log.debug(
                        f"periodic_token_refresh UNSUCCESSFUL; waiting {5 * attempt} sec before retrying")
                    sleep(5 * attempt)
                else:
                    break
            periodic_token_refresh()

        name = 'Tread-periodic_token_refresh'
        macmarrum_log.debug(f"START {name}")
        Thread(target=periodic_token_refresh, name=name).start()


if __name__ == '__main__':
    for a in sys.argv:
        if a.startswith('--record='):
            Macmarrum357().record(a.removeprefix('--record='))
            break
    else:  # no break
        Macmarrum357().play()
