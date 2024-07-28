#!/usr/bin/python3
# macmarrum357 – an alternative CLI player for Radio357 patrons
# Copyright (C) 2024  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import http.client
import json
import logging
import logging.config
import os
import pickle
import re
import shlex
import subprocess
import sys
import threading
import traceback
from collections.abc import Callable, Sequence, Iterator
from datetime import datetime, timedelta, timezone
from http.cookiejar import MozillaCookieJar, CookieJar, Cookie
from pathlib import Path
from time import sleep, time

import requests
from requests.cookies import RequestsCookieJar

me = Path(__file__)

__version__ = '2024.07.13'

UTF8 = 'UTF-8'

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
            "format": "{asctime} {levelname:5} {name:22} | {message}",
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


def mk_filename(start: datetime, end: datetime, duration: timedelta, file_num: int, count: int):
    return f"{start.strftime('%Y-%m-%d,%a_%H')}.aac"


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
    CAPPING_TIMESTAMP = 'cappingTimestamp'
    ACCEPT = 'Accept'
    APPLICATION_JSON = 'application/json'
    ACCEPT_ENCODING = 'Accept-Encoding'


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

    Alternatively, `--record='{"output_dir": "/path/to/directory", "switch_file_times":"[6, 9, 12]"}'
    """
    STREAM = 'https://stream.radio357.pl/'
    REDCDN_LIVE = 'https://r.dcs.redcdn.pl/sc/o2/radio357/live/radio357_pr.livx'
    USER_AGENT = 'macmarrum/357'
    UA_HEADERS = {c.USER_AGENT: USER_AGENT}
    AE_HEADERS = {c.ACCEPT: 'audio/aac', c.ACCEPT_ENCODING: 'identity'}
    ACCEPT_JSON_HEADERS = {c.ACCEPT: c.APPLICATION_JSON}
    TOKEN_VALIDITY_DELTA = timedelta(minutes=60)
    RECORD_CHUNK_SIZE = 8192
    config_json_path = macmarrum357_path / 'config.json'
    cookies_pickle_path = macmarrum357_path / 'cookies.pickle'
    cookies_txt_path = macmarrum357_path / 'cookies.txt'

    def __init__(self):
        self.init_datetime = datetime.now(timezone.utc).astimezone()
        macmarrum_log.debug(f"Macmarrum357() {self.init_datetime.date().isoformat()}")
        self.conf = {}
        self.load_config()
        # self.init_logging()
        self.session = requests.Session()
        self.load_cookies()
        self.is_cookies_changed = False
        self.record_hour = None
        self.is_playing_or_recoding = False

    def load_config(self):
        if not self.config_json_path.exists():
            with self.config_json_path.open('w') as fo:
                conf = {c.EMAIL: '', c.PASSWORD: ''}
                if os.name == 'nt':
                    conf |= {c.MPV_COMMAND: 'mpv', c.MPV_OPTIONS: ['--force-window=immediate']}
                json.dump(conf, fo, indent=2)
        else:
            with self.config_json_path.open('r') as fi:
                conf = json.load(fi)
                macmarrum_log.debug(f"LOAD {self.config_json_path.name} {conf}")
        assert conf.get(c.EMAIL) and conf.get(
            c.PASSWORD), f"{self.config_json_path} is missing email and/or password values"
        self.conf = conf

    def load_cookies(self):
        msg = f"LOAD {self.cookies_pickle_path.name}"
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

    def play(self):
        self.ensure_login_done()
        self.persist_cookies_if_changed()
        self.is_playing_or_recoding = True
        self.run_periodic_token_refresh_thread()
        sleep_if_requested()
        self.run_mpv()
        self.is_playing_or_recoding = False

    def ensure_login_done(self):
        resp = self.refresh_or_login_and_query_to_verify()
        assert resp.status_code == 200, f"{resp.status_code} {resp.text}"
        self.init_r357_and_set_cookies_changed_if_needed()

    def init_r357_and_set_cookies_changed_if_needed(self):
        r357_pid = self.get_cookie(c.R357_PID)
        self.init_r357()
        r357_pid_new = self.get_cookie(c.R357_PID)
        if r357_pid_new.value != r357_pid.value or r357_pid_new.expires != r357_pid.expires:
            self.is_cookies_changed = True

    def get_cookie(self, name, domain=None):
        if domain:
            session_cookies_for_domain = (k for k in self.session.cookies if k.domain == domain)
        else:
            session_cookies_for_domain = self.session.cookies
        for cookie in session_cookies_for_domain:
            if cookie.name == name:
                return cookie
        return Cookie(None, name, None, None, False, '', False, False,
                      '', False, False, 0, False, None, None, {}, False)

    def init_r357(self):
        macmarrum_log.debug('INIT r357_pid')
        url = 'https://checkout.radio357.pl/user/init/'
        resp = self.session.get(url, headers=self.UA_HEADERS)
        assert resp.status_code == 200, f"{resp.status_code} {resp.text}"
        assert self.session.cookies.get(c.R357_PID), f"{c.R357_PID} is missing. This is unexpected."

    def persist_cookies_if_changed(self):
        if self.is_cookies_changed:
            self.dump_cookies_pickle()
            self.save_cookies_txt()
            self.is_cookies_changed = False

    def dump_cookies_pickle(self):
        def target():
            macmarrum_log.debug(f"WRITE {self.cookies_pickle_path.name}")
            cj = self.session.cookies.copy()
            cj.clear_session_cookies()
            cj.clear_expired_cookies()
            # for cookie_line in iter_mozilla_cookies_as_csv(cj):
            #     macmarrum_log.debug(f"WRITE {self.macmarrum357_cookies_pickle_path.name} {cookie_line}")
            with self.cookies_pickle_path.open('wb') as fo:
                pickle.dump(cj, fo)

        threading.Thread(target=target, name='dump_cookies_pickle').start()

    def save_cookies_txt(self):
        macmarrum_log.debug(f"WRITE {self.cookies_txt_path.name}")
        mcj = MozillaCookieJar()
        for cookie in self.session.cookies:
            mcj.set_cookie(cookie)
        mcj.clear_session_cookies()
        mcj.clear_expired_cookies()
        # for cookie_line in iter_mozilla_cookies_as_csv(mcj):
        #     macmarrum_log.debug(f"WRITE {self.macmarrum357_cookies_txt_path.name} {cookie_line}")
        mcj.save(self.cookies_txt_path.as_posix())

    def query_account(self):
        macmarrum_log.debug('QUERY account')
        url = 'https://auth.r357.eu/api/account'
        token = self.session.cookies.get(c.TOKEN)
        headers = self.UA_HEADERS | {c.AUTHORIZATION: f"{c.BEARER} {token}"}
        return self.session.get(url, headers=headers)

    def refresh_or_login_and_query_to_verify(self):
        # try to refresh the token before falling back to login
        is_to_login = False
        refresh_token_cookie = self.get_cookie(c.REFRESH_TOKEN)
        if not refresh_token_cookie.value:
            is_to_login = True
        elif time() > refresh_token_cookie.expires - 55 * 60:  # it's been more than 5 min since last refresh
            resp = self.refresh_token()
            if resp.status_code == 200:
                self.update_and_persist_tokens_from_resp(resp)
            else:
                macmarrum_log.debug(f"UNSUCCESSFUL refresh {resp.status_code} {resp.text}")
                is_to_login = True
        if is_to_login:
            resp = self.login()
            if resp.status_code == 200:
                self.update_and_persist_tokens_from_resp(resp)
            else:
                macmarrum_log.error(f"login was UNSUCCESSFUL - {resp.status_code} {resp.text}")
        # query account to see if the new token works
        return self.query_account()

    def refresh_token(self):
        macmarrum_log.debug('REFRESH token')
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

    def login(self):
        macmarrum_log.debug('LOGIN to get new tokens')
        url = 'https://auth.r357.eu/api/auth/login'
        credentials = {c.EMAIL: self.conf[c.EMAIL], c.PASSWORD: self.conf[c.PASSWORD]}
        headers = self.UA_HEADERS | self.ACCEPT_JSON_HEADERS
        return self.session.post(url, headers=headers, json=credentials)

    def run_mpv(self):
        mpv = self.conf.get(c.MPV_COMMAND, 'mpv')
        mpv_args = self.conf.get(c.MPV_OPTIONS, [])
        ae_headers = ','.join(f"'{k}: {v}'" for k, v in self.AE_HEADERS.items())
        args = [mpv,
                self.STREAM,
                f"--user-agent={self.USER_AGENT}",
                '--cookies=yes',
                f"--cookies-file={self.cookies_txt_path}",
                f"--http-header-fields={ae_headers}",
                # add any args specified in macmarrum357.json
                *mpv_args,
                # add any args passed on the command line
                *sys.argv[1:]
                ]
        macmarrum_log.debug(f"RUN [{' '.join(quote(a) for a in args)}]")
        try:
            with subprocess.run(args, stderr=subprocess.PIPE) as proc:
                # Note: all stderr is logged at one go, after the command finishes
                for b_line in proc.stderr.read().splitlines(keepends=False):
                    macmarrum_log.warning(b_line.decode(UTF8))
        except FileNotFoundError as e:
            macmarrum_log.critical(f"'mpv_command' might be missing or incorrect in {self.config_json_path}")
            raise
        except Exception as e:
            macmarrum_log.critical(f"{type(e).__name__} {e} {traceback.format_exc()}")
            raise
        finally:
            self.is_playing_or_recoding = False

    def record(self):
        args_as_json = None
        for arg in sys.argv:
            if arg.startswith('--record='):
                args_as_json = arg.removeprefix('--record=')
                break
        macmarrum_log.debug(f"{args_as_json=}")
        record_args = json.loads(args_as_json)
        macmarrum_log.debug(f"{record_args=}")
        self.start_recording(**record_args)

    def start_recording(self, output_dir: str | Path = None, filename: str | Callable | None = None,
                        switch_file_times: Sequence[str | int | datetime] = ('*:00', '00:00'),
                        on_file_start: str | Callable | None = None, on_file_end: str | Callable | None = None):
        """
        :param output_dir: path to the output directory; if missing: current working directory
        :param filename: file name or a callable to create it based on switch_file_times date/time;
         if missing: mk_filename(...) which returns `%Y-%m-%d,%a_%H.aac`, based on start time
        :param switch_file_times: a sequence of time spec `HH:MM:SS`, e.g. ('6:00', '9:00', '12:00'),
         the last one meaning stop; special syntax exists to switch file every hour (`*`),
         e.g. when run at 6:00, the following ('*:00', '9:00') will produce 3 1-hour files: 6:00, 7:00 and 8:00
        :param on_file_start: command to spawn at each file switch, after starting a file;
         if `mpv_command`, mpv_options from config are also used;
         if it's a callable, make sure to use non-blocking code
        :param on_file_end: command to spawn at each file switch, after ending a file;
         if it's a callable, make sure to use non-blocking code;
         example bash script: `/usr/bin/ffmpeg -i "$1" -acodec copy "${1%.aac}.m4a"`
        """
        self.is_playing_or_recoding = True
        if output_dir is None:
            output_dir = Path().absolute()
        if filename is None:
            filename = mk_filename

        switch_file_datetime = SwitchFileDateTime(switch_file_times)
        count = switch_file_datetime.count
        switch_file_datetime_iterator = switch_file_datetime.iterator

        def start_file_out():
            file_num, start, end, duration = next(switch_file_datetime_iterator)
            output_path = Path(output_dir) / filename(start=start, end=end, duration=duration, file_num=file_num,
                                                      count=count) if callable(filename) else filename
            macmarrum_log.info(f"RECORD {file_num}/{count} {duration} to {output_path}")
            if output_path.exists():
                macmarrum_log.warning(f"Writing to an existing file: {output_path}")
            return output_path, output_path.open('wb'), file_num, end

        def spawn_on_file_start_if_requested(path):
            if on_file_start is not None:
                if callable(on_file_start):
                    on_file_start(path)
                else:
                    if on_file_start == 'mpv_command':
                        mpv_command = self.conf.get(c.MPV_COMMAND, 'mpv')
                        mpv_options = self.conf.get(c.MPV_OPTIONS, [])
                        args = [mpv_command, *mpv_options, f"appending://{path}"]
                    else:
                        args = [on_file_start, str(path)]
                    macmarrum_log.debug(f"SPAWN [{' '.join(quote(a) for a in args)}]")
                    with subprocess.Popen(args, stderr=subprocess.PIPE) as proc:
                        # Note: all stderr is logged at one go, after the command finishes
                        for b_line in proc.stderr.read().splitlines(keepends=False):
                            macmarrum_log.warning(b_line.decode(UTF8))

        def spawn_on_file_end_if_requested(path):
            if on_file_end is not None:
                if callable(on_file_end):
                    on_file_end(path)
                else:
                    args = [on_file_end, str(path)]
                    macmarrum_log.info(f"SPAWN [{' '.join(quote(a) for a in args)}]")
                    with subprocess.Popen(args, stderr=subprocess.PIPE) as proc:
                        # Note: all stderr is logged at one go, after the command finishes
                        for b_line in proc.stderr.read().splitlines(keepends=False):
                            macmarrum_log.warning(b_line.decode(UTF8))

        self.run_periodic_token_refresh_thread()
        sleep_if_requested(self.init_datetime)
        try:
            file_path, fo, num, end_dt = start_file_out()
            url = self.STREAM
            headers = self.UA_HEADERS | self.AE_HEADERS
            capping_timestamp_cookie = self.get_cookie(c.CAPPING_TIMESTAMP, '.radio357.pl.cdns-redge.media')
            while True:
                macmarrum_log.debug(f"URL {url}")
                resp = self.session.get(url, headers=headers, stream=True, allow_redirects=False)
                if 'radio357.pl.cdns-redge.media' in url:
                    a = capping_timestamp_cookie
                    b = self.get_cookie(c.CAPPING_TIMESTAMP, '.radio357.pl.cdns-redge.media')
                    a_expires = datetime.fromtimestamp(a.expires).astimezone().isoformat()
                    b_expires = datetime.fromtimestamp(b.expires).astimezone().isoformat()
                    macmarrum_log.debug(
                        f"{c.CAPPING_TIMESTAMP} {b.value} expires {b_expires} | previous {a.value}: {a_expires}")
                if resp.is_redirect:
                    url = resp.headers['location']
                    if url == self.REDCDN_LIVE:
                        macmarrum_log.debug('### URL += ?preroll=0')
                        url += '?preroll=0'
                else:
                    resp.raise_for_status()
                    self.dump_cookies_pickle()
                    break
            spawn_on_file_start_if_requested(file_path)
            for chunk in resp.iter_content(chunk_size=self.RECORD_CHUNK_SIZE):
                fo.write(chunk)
                if end_dt and datetime.now(timezone.utc) >= end_dt:
                    fo.close()
                    spawn_on_file_end_if_requested(file_path)
                    try:
                        file_path, fo, num, end_dt = start_file_out()
                    except StopIteration:
                        break
                    else:
                        spawn_on_file_start_if_requested(file_path)
            if fo and not fo.closed:
                fo.close()
        except Exception as e:
            macmarrum_log.critical(f"{type(e).__name__} {e} {traceback.format_exc()}")
            raise
        finally:
            self.is_playing_or_recoding = False

    def run_periodic_token_refresh_thread(self):
        name = 'periodic_token_refresh'
        macmarrum_log.info(f"START Thread {name}")
        _24h_as_seconds = 24 * 60 * 60
        _5m_as_seconds = 5 * 60

        def periodic_token_refresh():
            macmarrum_log.debug('RUN periodic_token_refresh')
            if time() > self.get_cookie(c.R357_PID).expires - _24h_as_seconds:
                self.init_r357_and_set_cookies_changed_if_needed()
            expires = self.get_cookie(c.TOKEN).expires
            expires_with_margin = expires - _5m_as_seconds
            while time() < expires_with_margin:
                if not self.is_playing_or_recoding:
                    return
                sleep(5)
            attempt = 0
            while True:
                attempt += 1
                macmarrum_log.debug(f"periodic_token_refresh ATTEMPT {attempt}")
                resp = self.refresh_or_login_and_query_to_verify()
                if resp.status_code != 200 and self.is_playing_or_recoding:
                    msg = f"periodic_token_refresh UNSUCCESSFUL; waiting {5 * attempt} sec before retrying"
                    macmarrum_log.debug(msg)
                    sleep(5 * attempt)
                else:
                    break
            if self.is_playing_or_recoding:
                periodic_token_refresh()

        threading.Thread(target=periodic_token_refresh, name=name).start()

    def run_get_now_playing(self):
        url = 'https://stream.radio357.pl/now/playing.json'
        params = {'t': int(time() * 1000)}
        cookies = self.session.cookies
        self.session.cookies = RequestsCookieJar()
        self.session.get(url, headers=self.UA_HEADERS, params=params, stream=True)
        self.session.cookies = cookies


SwitchFileIterator = Iterator[tuple[int, datetime, datetime, timedelta]]


class SwitchFileDateTime:
    HOURS1 = timedelta(hours=1)
    DAYS1 = timedelta(days=1)
    RX_H_MM_SS = re.compile(r'^(\*|\d{1,2})(:\d{1,2}){0,2}$')
    FMT = '%H:%M:%S'

    def __init__(self, switch_file_times: Sequence[str | int | datetime]):
        self._is_all_datetime = None
        self._switch_file_times = switch_file_times
        sft_for_log = [e.strftime(self.FMT) for e in switch_file_times] if self.is_all_datetime else switch_file_times
        macmarrum_log.debug(f"SwitchFileDateTime switch_file_times={sft_for_log}")
        self._is_every_hour = None
        self._validate()
        self._parsed_switch_file_times = None
        self._count = None

    def _validate(self):
        switch_file_times = self._switch_file_times
        switch_file_times_len = len(switch_file_times)
        assert switch_file_times_len > 0, f"expected size > 0, got {switch_file_times_len}"
        if self.is_every_hour:
            assert switch_file_times_len == 2, f"expected size == 2, got {switch_file_times_len}"
        assert self.is_all_datetime or all(isinstance(e, int) or self.RX_H_MM_SS.match(e) for e in switch_file_times)

    @property
    def is_all_datetime(self):
        if self._is_all_datetime is None:
            self._is_all_datetime = all(isinstance(elem, datetime) for elem in self._switch_file_times)
        return self._is_all_datetime

    @property
    def is_every_hour(self):
        if self._is_every_hour is None:
            elem0 = self._switch_file_times[0]
            self._is_every_hour = isinstance(elem0, str) and elem0.startswith('*')
        return self._is_every_hour

    @property
    def parsed_switch_file_times(self):
        if self._parsed_switch_file_times is None:
            self._parse()
        return self._parsed_switch_file_times

    @property
    def iterator(self):
        if self.is_all_datetime:
            return self._mk_iterator_for_datetime_args()
        elif self.is_every_hour:
            return self._mk_iterator_for_asterisk_arg0()
        else:
            return self._mk_iterator_for_regular_args()

    @property
    def count(self) -> int:
        """
        Runs the iterator, using previous iteration's end as the start, i.e. perfect time periods
        and counts the number of iterations

        :return: count of iterations (files)
        """
        if self._count is None:
            now = datetime.now(timezone.utc).astimezone()
            if self.is_all_datetime:
                iterator = self._mk_iterator_for_datetime_args(now)
            elif self.is_every_hour:
                iterator = self._mk_iterator_for_asterisk_arg0(now)
            else:
                iterator = self._mk_iterator_for_regular_args(now)
            FMT = self.FMT
            i = 0
            for e in iterator:
                i += 1
                macmarrum_log.debug(f"SwitchFileDateTime {e[0]}: [{e[1].strftime(FMT)}, {e[2].strftime(FMT)}]")
            self._count = i
        return self._count

    def _parse(self):
        parsed_switch_file_times = []
        for elem in self._switch_file_times:
            if isinstance(elem, int):
                h = elem
                m = s = 0
            else:
                lst = elem.split(':')
                lst_size = len(lst)
                if lst_size == 3:
                    h, m, s = lst
                elif lst_size == 2:
                    h, m = lst
                    s = 0
                elif lst_size == 1:
                    h = elem
                    m = s = 0
                else:
                    raise ValueError(f"expected from 1 to 3 parts, found {lst_size}")
                h = None if h == '*' else int(h)
                m = int(m)
                s = int(s)
            parsed_switch_file_times.append((h, m, s))
        self._parsed_switch_file_times = parsed_switch_file_times
        macmarrum_log.debug(f"SwitchFileDateTime {parsed_switch_file_times=}")
        return parsed_switch_file_times

    def _mk_iterator_for_datetime_args(self, _now: datetime = None) -> SwitchFileIterator:
        start = end = _now or datetime.now(timezone.utc).astimezone()
        for file_num, dt in enumerate(self._switch_file_times, start=1):
            # for testing, new start is previous end, otherwise real time
            start = end if _now else datetime.now(timezone.utc).astimezone()
            # end is the entry from the list
            end = dt
            duration = end - start
            yield file_num, start, end, duration

    def _mk_iterator_for_regular_args(self, _now: datetime = None) -> SwitchFileIterator:
        start = end = _now or datetime.now(timezone.utc).astimezone()
        file_num = 0
        h_m_s: tuple[int | None, int, int]
        for i, h_m_s in enumerate(self.parsed_switch_file_times):
            # for testing, new start is previous end, otherwise real time
            start = end if _now else datetime.now(timezone.utc).astimezone()
            # end is the entry from the list
            h, m, s = h_m_s
            end = start.replace(hour=h, minute=m, second=s, microsecond=0)
            if end < start:
                end += self.DAYS1
            duration = end - start
            file_num += 1
            yield file_num, start, end, duration

    def _mk_iterator_for_asterisk_arg0(self, _now: datetime = None) -> SwitchFileIterator:
        start = _now or datetime.now(timezone.utc).astimezone()
        h, m, s = self.parsed_switch_file_times[0]
        final_h, final_m, final_s = self.parsed_switch_file_times[1]
        final_end = start.replace(hour=final_h, minute=final_m, second=final_s, microsecond=0)
        if final_end < start:
            final_end += self.DAYS1
        end = (start + self.HOURS1).replace(minute=m, second=s, microsecond=0)
        file_num = 1
        yield file_num, start, end, end - start
        while end < final_end:
            # for testing, new start is previous end, otherwise real time
            start = end if _now else datetime.now(timezone.utc).astimezone()
            # new end is start + 1h
            end = start + self.HOURS1
            # end is at the specified minutes and seconds of the hour
            end = end.replace(minute=m, second=s, microsecond=0)
            if end < start:
                end += self.DAYS1
            duration = end - start
            file_num += 1
            yield file_num, start, end, duration


def run_record_or_play():
    for arg in sys.argv:
        if arg.startswith('--record='):
            Macmarrum357().record()
            break
    else:  # no break
        Macmarrum357().play()


if __name__ == '__main__':
    configure_logging()
    run_record_or_play()
