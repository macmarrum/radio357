#!/usr/bin/python3
# macmarrum357 – an alternative CLI player for Radio357 patrons
# Copyright (C) 2024  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import http.client
import json
import logging.config
import os
import pickle
import shlex
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from http.cookiejar import MozillaCookieJar, CookieJar, Cookie
from pathlib import Path
from time import time, sleep

import requests
from requests.cookies import RequestsCookieJar

macmarrum_log = logging.getLogger('macmarrum357')
requests_log = logging.getLogger('urllib3')
http_client_log = logging.getLogger('http.client')


def get_appdata() -> Path:
    if os.name == 'nt':
        return Path(os.environ['APPDATA'])
    elif os.name == 'posix':
        return Path(os.environ.get('XDG_CONFIG_HOME', '~/.config')).expanduser()
    else:
        raise RuntimeError(f"unknown os.name: {os.name}")


macmarrum357_path = get_appdata() / 'macmarrum357'
macmarrum357_path.mkdir(exist_ok=True)
logging_json_path = macmarrum357_path / 'logging.json'

LOGGING_CONFIG_DEFAULT = {
    "version": 1,
    "filters": {
        "hide_reply_header": {
            "()": "macmarrum357.mk_hide_reply_header_filter"
        },
        "hide_urllib3_reply_https": {
            "()": "macmarrum357.mk_hide_urllib3_reply_https_filter"
        }
    },
    "formatters": {
        "formatter": {
            "format": "{asctime} {levelname:7} {name:22} | {message}",
            "style": "{",
            "validate": True
        }
    },
    "handlers": {
        "to_console": {
            "class": "logging.StreamHandler",
            "formatter": "formatter",
            "filters": ["hide_urllib3_reply_https"]
        },
        "to_file": {
            "class": "logging.FileHandler",
            "filename": "macmarrum357.log",
            "encoding": "UTF-8",
            "formatter": "formatter",
            "filters": ["hide_urllib3_reply_https"]
        }
    },
    "loggers": {
        "macmarrum357": {
            "level": "INFO",
            "handlers": [
                "to_console",
                "to_file"
            ]
        },
        "urllib3": {
            "level": "INFO",
            "handlers": [
                "to_console",
                "to_file"
            ]
        },
        "http.client": {
            "level": "INFO",
            "filters": ["hide_reply_header"],
            "handlers": [
                "to_console",
                "to_file"
            ]
        }
    }
}


def mk_hide_reply_header_filter():
    def should_log_record(record: logging.LogRecord) -> bool:
        return not record.msg.startswith('header: ')

    return should_log_record


def mk_hide_urllib3_reply_https_filter():
    name = 'urllib3.connectionpool'
    msg = '%s://%s:%s "%s %s %s" %s %s'

    def should_log_record(record: logging.LogRecord) -> bool:
        if record.name.startswith(name):
            # print(f">> {record.msg}")
            return not record.msg.startswith(msg)
        else:
            return True

    return should_log_record


def configure_logging():
    if not logging_json_path.exists():
        with logging_json_path.open('w') as fo:
            json.dump(LOGGING_CONFIG_DEFAULT, fo, indent=2)
            dict_config = LOGGING_CONFIG_DEFAULT
    else:
        with logging_json_path.open('r') as fi:
            dict_config = json.load(fi)
    logging.config.dictConfig(dict_config)
    if http_client_log.level == logging.DEBUG:
        http.client.HTTPConnection.debuglevel = 1
        http.client.print = lambda *args: http_client_log.debug(' '.join(args))


def sleep_if_requested(start_time: datetime | None = None):
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
        if start_time is None:
            sleep(sleep_sec)
        else:
            end_time = start_time + timedelta(seconds=sleep_sec)
            sleep_interval = min(sleep_sec / 100, 0.5)
            macmarrum_log.info(f"sleeping for {sleep_sec} seconds, until {end_time.isoformat(sep=' ')}")
            while datetime.now(timezone.utc) < end_time:
                sleep(sleep_interval)


def iter_mozilla_cookies_as_csv(cookiejar: RequestsCookieJar | CookieJar, sep: str = ' '):
    for cookie in cookiejar:
        yield mk_mozilla_cookie_csv(cookie, sep)


def mk_mozilla_cookie_csv(cookie: Cookie, sep: str = ' '):
    expires = datetime.fromtimestamp(cookie.expires).astimezone().isoformat()
    return f"{cookie.domain}{sep}{cookie.domain_initial_dot}{sep}{cookie.path}{sep}{cookie.secure}{sep}{expires}{sep}{cookie.name}{sep}{cookie.value}"


def quote(x):
    return shlex.quote(x)


class c:
    EMAIL = 'email'
    PASSWORD = 'password'
    USER_AGENT = 'User-Agent'
    AUTHORIZATION = 'Authorization'
    BEARER = 'Bearer'
    R357_PID = 'r357_pid'
    REFRESH_TOKEN = 'refresh_token'
    REFRESH_TOKEN_EXPIRES = 'refresh_token_expires'
    ACCESS_TOKEN = 'accessToken'
    REFRESHTOKEN = 'refreshToken'
    TOKEN = 'token'
    TOKEN_EXPIRES = 'token_expires'
    MPV_COMMAND = 'mpv_command'
    MPV_OPTIONS = 'mpv_options'
    ACCEPT = 'Accept'
    APPLICATION_JSON = 'application/json'
    ACCEPT_ENCODING = 'Accept-Encoding'
    LOCATION = 'location'


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
    will silently record 60 minutes of the stream to output.aac
    """
    STREAM = 'https://stream.radio357.pl/'
    REDCDN_LIVE_NO_PREROLL = 'https://r.dcs.redcdn.pl/sc/o2/radio357/live/radio357_pr.livx'
    LOCATION_REPLACEMENTS = {REDCDN_LIVE_NO_PREROLL: REDCDN_LIVE_NO_PREROLL + '?preroll=0'}
    USER_AGENT = 'macmarrum/357'
    TOKEN_VALIDITY_DELTA = timedelta(minutes=60)
    UA_HEADERS = {c.USER_AGENT: USER_AGENT}
    AE_HEADERS = {c.ACCEPT: 'audio/aac', c.ACCEPT_ENCODING: 'identity'}
    ACCEPT_JSON_HEADERS = {c.ACCEPT: c.APPLICATION_JSON}
    config_json_path = macmarrum357_path / 'config.json'
    cookies_pickle_path = macmarrum357_path / 'cookies.pickle'
    cookies_txt_path = macmarrum357_path / 'cookies.txt'

    def __init__(self):
        self.init_datetime = datetime.now(timezone.utc).astimezone()
        macmarrum_log.info(f"Macmarrum357() {self.init_datetime.date().isoformat()}")
        self.conf = {}
        self.load_config()
        self.session = requests.Session()
        self.load_cookies()
        self.is_cookies_changed = False
        self.url = self.conf.get('live_stream_url', self.STREAM)
        self.location_replacements = self.conf.get('live_stream_location_replacements', self.LOCATION_REPLACEMENTS)

    def load_config(self):
        if not self.config_json_path.exists():
            with self.config_json_path.open('w') as fo:
                conf = {c.EMAIL: '', c.PASSWORD: '', c.MPV_COMMAND: 'mpv', c.MPV_OPTIONS: ['--force-window=immediate', '--cache-secs=1', '--fs=no']}
                json.dump(conf, fo, indent=2)
        else:
            with self.config_json_path.open('r') as fi:
                conf = json.load(fi)
                macmarrum_log.debug(f"load_config {self.config_json_path.name} {conf}")
        assert conf.get(c.EMAIL) and conf.get(
            c.PASSWORD), f"{self.config_json_path} is missing email and/or password values"
        self.conf = conf

    def load_cookies(self):
        msg = f"load_cookies {self.cookies_pickle_path.name}"
        macmarrum_log.debug(msg)
        try:
            with self.cookies_pickle_path.open('rb') as fi:
                cj: RequestsCookieJar = pickle.load(fi)
                # for cookie_line in iter_mozilla_cookies_as_csv(cj):
                #     macmarrum_log.debug(f"LOAD {self.macmarrum357_cookies_pickle_path.name} {cookie_line}")
                self.session.cookies.update(cj)
        except (FileNotFoundError, EOFError) as e:
            macmarrum_log.debug(f"{msg} - {type(e).__name__}: {e}")
            pass

    def run(self):
        try:
            self.refresh_or_login()
            headers = self.UA_HEADERS | self.AE_HEADERS
            while True:
                macmarrum_log.debug(f"live-stream url {self.url}")
                with self.session.get(self.url, headers=headers, stream=True, allow_redirects=False) as resp:
                    if resp.is_redirect:
                        location = resp.headers[c.LOCATION]
                        if replacement := self.location_replacements.get(location):
                            macmarrum_log.debug(f"replace location to {replacement}")
                            location = replacement
                        self.url = location
                    else:
                        resp.raise_for_status()
                        break
            with self.mk_query_account_resp() as resp:
                if resp.status_code == 200:
                    self.persist_cookies_if_changed()
                else:
                    resp.raise_for_status()
            resp.close()
            sleep_if_requested()
            self.spawn_mpv()
            self.run_periodic_token_refresh_thread()
        except KeyboardInterrupt:
            pass
        finally:
            self.session.close()

    def get_cookie(self, name):
        for cookie in self.session.cookies:
            if cookie.name == name:
                return cookie
        return Cookie(None, name, None, None, False, '', False, False,
                      '', False, False, 0, False, None, None, {}, False)

    def dump_cookies_pickle(self):
        macmarrum_log.debug('dump_cookies_pickle')
        cj = self.session.cookies.copy()
        cj.clear_session_cookies()
        cj.clear_expired_cookies()
        # for cookie_line in iter_mozilla_cookies_as_csv(cj):
        #     macmarrum_log.debug(f"WRITE {self.macmarrum357_cookies_pickle_path.name} {cookie_line}")
        with self.cookies_pickle_path.open('wb') as fo:
            pickle.dump(cj, fo)

    def save_cookies_txt(self):
        macmarrum_log.debug('save_cookies_txt')
        mcj = MozillaCookieJar()
        for cookie in self.session.cookies:
            mcj.set_cookie(cookie)
        mcj.clear_session_cookies()
        mcj.clear_expired_cookies()
        # for cookie_line in iter_mozilla_cookies_as_csv(mcj):
        #     macmarrum_log.debug(f"WRITE {self.macmarrum357_cookies_txt_path.name} {cookie_line}")
        mcj.save(self.cookies_txt_path.as_posix())

    def run_periodic_token_refresh_thread(self):
        macmarrum_log.info(f"run_periodic_token_refresh_thread")
        macmarrum_log.info(f"press Ctrl+C to exit")
        _24h_as_seconds = 24 * 60 * 60
        _5m_as_seconds = 5 * 60

        def periodic_token_refresh():
            macmarrum_log.debug('periodic_token_refresh (wait until it\'s time)')
            if time() > self.get_cookie(c.R357_PID).expires - _24h_as_seconds:
                self.init_r357_and_set_cookies_changed_if_needed()
            expires = self.get_cookie(c.TOKEN).expires
            expires_with_margin = expires - _5m_as_seconds
            while time() < expires_with_margin:
                sleep(5)
            attempt = 0
            while True:
                attempt += 1
                macmarrum_log.debug(f"periodic_token_refresh attempt {attempt}")
                self.refresh_or_login()
                with self.mk_query_account_resp() as resp:
                    if resp.status_code == 200:
                        self.persist_cookies_if_changed()
                        break
                    else:
                        msg = f"periodic_token_refresh unsuccessful; waiting {5 * attempt} sec before retrying"
                        macmarrum_log.debug(msg)
                        sleep(5 * attempt)
            periodic_token_refresh()

        periodic_token_refresh()

    def init_r357_and_set_cookies_changed_if_needed(self):
        r357_pid = self.get_cookie(c.R357_PID)
        self.init_r357()
        r357_pid_new = self.get_cookie(c.R357_PID)
        if r357_pid_new.value != r357_pid.value or r357_pid_new.expires != r357_pid.expires:
            self.is_cookies_changed = True

    def init_r357(self):
        macmarrum_log.debug('init_r357')
        url = 'https://checkout.radio357.pl/user/init/'
        with self.session.get(url, headers=self.UA_HEADERS) as resp:
            assert resp.status_code == 200, f"{resp.status_code} {resp.text}"
            assert self.session.cookies.get(c.R357_PID), f"{c.R357_PID} is missing. This is unexpected."

    def refresh_or_login(self):
        # try to refresh the token before falling back to login
        is_to_login = False
        refresh_token_cookie = self.get_cookie(c.REFRESH_TOKEN)
        if not refresh_token_cookie.value:
            is_to_login = True
        elif time() > refresh_token_cookie.expires - 55 * 60:  # it's been more than 5 min since last refresh
            with self.mk_refresh_token_resp() as resp:
                if resp.status_code == 200:
                    self.update_and_persist_tokens_from_resp(resp)
                else:
                    macmarrum_log.debug(f"refresh_token {resp.status_code}")
                    is_to_login = True
        if is_to_login:
            with self.mk_login_resp() as resp:
                if resp.status_code == 200:
                    self.update_and_persist_tokens_from_resp(resp)
                else:
                    macmarrum_log.error(f"login {resp.status_code}")

    def mk_refresh_token_resp(self):
        macmarrum_log.debug('refresh_token')
        url = 'https://auth.r357.eu/api/auth/refresh'
        refresh_token = self.session.cookies.get(c.REFRESH_TOKEN)
        headers = self.UA_HEADERS | self.ACCEPT_JSON_HEADERS
        return self.session.post(url, headers=headers, json={c.REFRESHTOKEN: refresh_token})

    def update_and_persist_tokens_from_resp(self, resp):
        def mk_cookie(name: str, value, expires):
            return Cookie(0, name, value, None, False, '.radio357.pl', True, True,
                          '/', True, True, expires, False, None, None, {}, False)

        macmarrum_log.debug(f"{resp.status_code} {resp.text}")
        d = resp.json()
        expires = int((datetime.now().replace(microsecond=0) + self.TOKEN_VALIDITY_DELTA).timestamp())
        self.session.cookies.set_cookie(mk_cookie(c.TOKEN, d[c.ACCESS_TOKEN], expires))
        self.session.cookies.set_cookie(mk_cookie(c.TOKEN_EXPIRES, f"{expires}000", expires))
        self.session.cookies.set_cookie(mk_cookie(c.REFRESH_TOKEN, d[c.REFRESHTOKEN], expires))
        self.session.cookies.set_cookie(mk_cookie(c.REFRESH_TOKEN_EXPIRES, f"{expires}000", expires))
        self.is_cookies_changed = True

    def mk_login_resp(self):
        macmarrum_log.debug('login')
        url = 'https://auth.r357.eu/api/auth/login'
        credentials = {c.EMAIL: self.conf[c.EMAIL], c.PASSWORD: self.conf[c.PASSWORD]}
        headers = self.UA_HEADERS | self.ACCEPT_JSON_HEADERS
        return self.session.post(url, headers=headers, json=credentials)

    def mk_query_account_resp(self):
        macmarrum_log.debug('query_account')
        url = 'https://auth.r357.eu/api/account'
        token = self.session.cookies.get(c.TOKEN)
        headers = self.UA_HEADERS | {c.AUTHORIZATION: f"{c.BEARER} {token}"}
        return self.session.get(url, headers=headers)

    def persist_cookies_if_changed(self):
        if self.is_cookies_changed:
            self.dump_cookies_pickle()
            self.save_cookies_txt()
            self.is_cookies_changed = False

    def spawn_mpv(self):
        mpv = self.conf.get(c.MPV_COMMAND, 'mpv')
        mpv_args = self.conf.get(c.MPV_OPTIONS, [])
        args = [Path(mpv).name,
                self.url,
                f"--user-agent={self.USER_AGENT}",
                '--cookies=yes',
                f"--cookies-file={self.cookies_txt_path}",
                # add any args specified in macmarrum357.json
                *mpv_args,
                # add any args passed on the command line
                *sys.argv[1:]
                ]
        macmarrum_log.info(f"spawn_mpv: {' '.join(quote(a) for a in args)}")
        try:
            subprocess.Popen(args)
        except FileNotFoundError:
            print(f"** '{c.MPV_COMMAND}' might be missing or incorrect in {self.config_json_path}")
            raise


if __name__ == '__main__':
    configure_logging()
    Macmarrum357().run()
