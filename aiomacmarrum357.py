#!/usr/bin/python3
# aiomacmarrum357 – an alternative CLI player/recorder for Radio357 patrons
# Copyright (C) 2024  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import email.utils
import http.client
import json
import logging.config
import os
import re
import selectors
import shlex
import subprocess
import sys
import traceback
from collections.abc import Iterator
from datetime import datetime, timezone, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from time import time, monotonic
from typing import Callable, Sequence

import aiofiles
import aiohttp
import yarl
from aiohttp import AsyncResolver, CookieJar, web
from aiohttp.web_runner import GracefulExit

macmarrum_log = logging.getLogger('macmarrum357')
token_log = logging.getLogger('macmarrum357.token')
web_log = logging.getLogger('macmarrum357.web')
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
            "()": "aiomacmarrum357.mk_hide_reply_header_filter"
        },
        "hide_urllib3_reply_https": {
            "()": "aiomacmarrum357.mk_hide_urllib3_reply_https_filter"
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
        "aiohttp": {
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


async def sleep_if_requested(start_time: datetime | None = None):
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
            await asyncio.sleep(sleep_sec)
        else:
            end_time = start_time + timedelta(seconds=sleep_sec)
            sleep_interval = min(sleep_sec / 100, 0.5)
            macmarrum_log.info(f"sleeping for {sleep_sec} seconds, until {end_time.isoformat(sep=' ')}")
            while datetime.now(timezone.utc) < end_time:
                await asyncio.sleep(sleep_interval)


def mk_filename(start: datetime, end: datetime, duration: timedelta, file_num: int, count: int):
    return f"{start.strftime('%Y-%m-%d,%a_%H')}.aac"


def quote(x):
    return shlex.quote(x)


class c:
    STREAM_URL = 'stream_url'
    EMAIL = 'email'
    PASSWORD = 'password'
    NAMESERVERS = 'nameservers'
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
    SET_COOKIE_ = 'Set-Cookie:'
    MAX_AGE = 'max-age'
    EXPIRES = 'expires'
    DOMAIN = 'domain'
    PATH = 'path'
    SECURE = 'secure'
    MPV_COMMAND = 'mpv_command'
    MPV_OPTIONS = 'mpv_options'
    CAPPING_TIMESTAMP = 'cappingTimestamp'
    ACCEPT = 'Accept'
    APPLICATION_JSON = 'application/json'
    ACCEPT_ENCODING = 'Accept-Encoding'
    LOCATION = 'location'
    AUDIO_AAC = 'audio/aac'
    IDENTITY = 'identity'
    HOST = 'host'
    PORT = 'port'


class Macmarrum357():
    STREAM = 'https://stream.radio357.pl/'
    REDCDN_LIVE_NO_PREROLL = 'https://r.dcs.redcdn.pl/sc/o2/radio357/live/radio357_pr.livx'
    LOCATION_REPLACEMENTS = {REDCDN_LIVE_NO_PREROLL: REDCDN_LIVE_NO_PREROLL + '?preroll=0'}
    USER_AGENT = 'macmarrum/357'
    UA_HEADERS = {c.USER_AGENT: USER_AGENT}
    AE_HEADERS = {c.ACCEPT: c.AUDIO_AAC, c.ACCEPT_ENCODING: c.IDENTITY}
    ACCEPT_JSON_HEADERS = {c.ACCEPT: c.APPLICATION_JSON}
    TOKEN_VALIDITY_DELTA = timedelta(minutes=60)
    ITER_CHUNK_SIZE = 4 * 1024
    HANDLER_START_BUFFER_SEC = 1.0
    QUEUE_MAX_LEN = 9
    QUEUE_COUNT_LIMIT = 99
    ITER_REC_CHUNK_SIZE = 8 * 1024
    ITER_REC_WAIT_SECS_FOR_DATA = 1
    config_json_path = macmarrum357_path / 'config.json'
    cookies_pickle_path = macmarrum357_path / 'cookies.pickle'
    cookies_txt_path = macmarrum357_path / 'cookies.txt'
    OUTPUT_FILE_MODE = 'ab'
    RX_TILDA_NUM = re.compile(r'(?<=~)\d+$')

    def __init__(self, web_app: web.Application = None):
        self.init_datetime = datetime.now(timezone.utc).astimezone()
        self.web_app = web_app
        macmarrum_log.debug(f"START Macmarrum357")
        self.conf = {}
        self.load_config()
        self.is_cookies_changed = False
        self.is_playing_or_recoding = False
        self.session: aiohttp.ClientSession = None
        self.location_replacements = self.conf.get('live_stream_location_replacements', self.LOCATION_REPLACEMENTS)
        self.queue_gen = ((asyncio.Queue(self.QUEUE_MAX_LEN), q) for q in range(self.QUEUE_COUNT_LIMIT))
        self._consumer_queues: list[asyncio.Queue] = []
        self.has_consumers = False
        self.file_path: Path = None

    def register_stream_consumer_to_get_queue(self):
        queue, q = next(self.queue_gen)
        self._consumer_queues.append(queue)
        self.has_consumers = True
        macmarrum_log.debug(f"register_stream_consumer #{q}")
        return queue, q

    def unregister_stream_consumer(self, queue, q):
        macmarrum_log.debug(f"unregister_stream_consumer #{q}")
        self._consumer_queues.remove(queue)
        self.has_consumers = len(self._consumer_queues) > 0

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
                macmarrum_log.debug(f"load_config {self.config_json_path.name} {conf}")
        assert conf.get(c.EMAIL) and conf.get(
            c.PASSWORD), f"{self.config_json_path} is missing email and/or password values"
        self.conf = conf

    async def run_client(self, output_dir: str | Path = None, filename: str | Callable | None = None,
                         switch_file_times: Sequence[str | int | datetime] = None,
                         on_file_start: str | Callable | None = None, on_file_end: str | Callable | None = None):
        self.is_playing_or_recoding = True
        should_record = switch_file_times is not None

        # https://github.com/netblue30/fdns/issues/47
        if nameservers := self.conf.get(c.NAMESERVERS):
            macmarrum_log.debug(f"using nameservers {nameservers}")
            try:
                connector = aiohttp.TCPConnector(resolver=AsyncResolver(nameservers=nameservers))
            except Exception as e:
                macmarrum_log.error(f"{type(e).__name__} {e}")
                raise
        else:
            connector = None
        # https://github.com/aio-libs/aiohttp/issues/3203
        # https://stackoverflow.com/questions/61199544/dealing-with-aiohttp-session-get-timeout-issues-for-large-amout-of-requests
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=5, sock_read=5)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        run_periodic_token_refresh_task = asyncio.create_task(self.run_periodic_token_refresh())

        if should_record:
            if output_dir is None:
                output_dir = Path().absolute()
            if filename is None:
                filename = mk_filename

            switch_file_datetime = SwitchFileDateTime(switch_file_times)
            count = switch_file_datetime.count
            switch_file_datetime_iter = switch_file_datetime.mk_iter()
            start_output_file_args = (output_dir, filename, switch_file_datetime_iter, count)

        await sleep_if_requested(self.init_datetime)
        resp = None
        fo = None
        end_dt = None
        try:
            url = self.conf.get(c.STREAM_URL, self.STREAM)
            headers = self.UA_HEADERS | self.AE_HEADERS
            macmarrum_log.debug(f"url {url}")
            while True:  # handle redirects
                if resp and not resp.closed:
                    resp.close()
                resp = await self.session.get(url, headers=headers, allow_redirects=False)
                location = resp.headers.get(c.LOCATION)
                if location:
                    macmarrum_log.debug(f"location: {location}")
                    if replacement := self.location_replacements.get(location):
                        macmarrum_log.debug(f"replace location to {replacement}")
                        location = replacement
                    url = location
                else:
                    resp.raise_for_status()
                    break
            if should_record:
                self.file_path, fo, num, end_dt = await self.start_output_file(*start_output_file_args)
                self.spawn_on_file_start_if_requested(on_file_start, self.file_path)

            async def iter_chunked(_resp, _fo, _end_dt):
                async for chunk in _resp.content.iter_chunked(self.ITER_CHUNK_SIZE):
                    if self.has_consumers:
                        for queue in self._consumer_queues:
                            await queue.put(chunk)
                    if should_record:
                        await _fo.write(chunk)
                        if _end_dt and datetime.now(timezone.utc) >= _end_dt:
                            await _fo.close()
                            self.spawn_on_file_end_if_requested(on_file_end, self.file_path)
                            try:
                                self.file_path, _fo, num, _end_dt = await self.start_output_file(*start_output_file_args)
                            except RuntimeError as e:
                                # https://docs.python.org/3/library/exceptions.html#StopIteration
                                if isinstance(e.__cause__, StopIteration):
                                    macmarrum_log.debug(f"{type(e).__name__} caused by {type(e.__cause__).__name__} -> break")
                                    raise
                                else:
                                    raise
                            else:
                                self.spawn_on_file_start_if_requested(on_file_start, self.file_path)

            i = 0
            while True:
                try:
                    await iter_chunked(resp, fo, end_dt)
                except Exception as e:
                    if isinstance(e.__cause__, StopIteration):
                        macmarrum_log.debug('End of switch_file_times - exiting')
                        break
                    else:
                        macmarrum_log.error(f"{type(e).__name__} {e}")
                        i += 1
                        if i > 60:
                            sec = 3600
                        elif i > 50:
                            sec = 600
                        elif i > 40:
                            sec = 300
                        elif i > 30:
                            sec = 60
                        elif i > 20:
                            sec = 30
                        elif i > 10:
                            sec = 5
                        elif i > 5:
                            sec = 2
                        elif i > 1:
                            sec = 1
                        else:
                            sec = 0
                        if sec:
                            macmarrum_log.debug(f"sleeping {sec}")
                            await asyncio.sleep(sec)
                        macmarrum_log.debug(f"retrying {url} {headers}")
                        resp = await self.session.get(url, headers=headers)
        except Exception as e:
            macmarrum_log.critical(f"{type(e).__name__} {e} {traceback.format_exc()}")
            raise
        finally:
            if resp and not resp.closed:
                resp.close()
            if not self.session.closed:
                await self.session.close()
            if fo and not fo.closed:
                await fo.close()
            self.is_playing_or_recoding = False
            await run_periodic_token_refresh_task
            if self.web_app:
                await self.web_app.shutdown()
                await self.web_app.cleanup()

    @classmethod
    async def start_output_file(cls, output_dir, filename, switch_file_datetime_iterator: Iterator, count: int):
        file_num, start, end, duration = next(switch_file_datetime_iterator)
        output_path = Path(output_dir) / filename(start=start, end=end, duration=duration, file_num=file_num,
                                                  count=count) if callable(filename) else filename
        is_filename_changed = False
        while 'a' not in cls.OUTPUT_FILE_MODE and output_path.exists():
            old_path = output_path
            stem = output_path.stem
            m = cls.RX_TILDA_NUM.search(stem)
            if m:
                num = int(m.group(0))
                new_stem = cls.RX_TILDA_NUM.sub(str(num + 1), stem)
            else:
                new_stem = f"{stem}~1"
            output_path = output_path.with_stem(new_stem)
            macmarrum_log.warning(f"File exists: {old_path}. Changing to {new_stem}{output_path.suffix}")
            is_filename_changed = True
        if not is_filename_changed and 'a' in cls.OUTPUT_FILE_MODE and output_path.exists():
            macmarrum_log.warning(f"Appending to an exiting file {output_path}")
        macmarrum_log.info(f"RECORD {file_num}/{count} {duration} to {output_path}")
        fo = await aiofiles.open(output_path, cls.OUTPUT_FILE_MODE)
        return output_path, fo, file_num, end

    def spawn_on_file_start_if_requested(self, on_file_start, path):
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
                subprocess.Popen(args)

    @staticmethod
    def spawn_on_file_end_if_requested(on_file_end, path):
        if on_file_end is not None:
            if callable(on_file_end):
                on_file_end(path)
            else:
                args = [on_file_end, str(path)]
                macmarrum_log.info(f"SPAWN [{' '.join(quote(a) for a in args)}]")
                subprocess.Popen(args)

    async def init_r357_and_set_cookies_changed_if_needed(self, logger=macmarrum_log):
        r357_pid = self.get_cookie(c.R357_PID)
        await self.init_r357(logger)
        r357_pid_new = self.get_cookie(c.R357_PID)
        if r357_pid_new.value != r357_pid.value or r357_pid_new.expires != r357_pid.expires:
            self.is_cookies_changed = True

    def get_cookie(self, name, domain=None):
        parse_date = aiohttp.cookiejar.CookieJar._parse_date
        # initial session has no cookies, so ignore
        if isinstance(self.session.cookie_jar, CookieJar):
            # macmarrum_log.debug(f"{self.session.cookie_jar._cookies=}")
            for cookie in self.session.cookie_jar:
                if domain and cookie[c.DOMAIN] != domain:
                    continue
                if cookie.key == name:
                    return MacmarrumCookie(name, cookie.value, parse_date(cookie[c.EXPIRES]))
        return MacmarrumCookie(name, '', 0)

    async def init_r357(self, logger=macmarrum_log):
        logger.debug('init_r357')
        url = 'https://checkout.radio357.pl/user/init/'
        async with self.session.get(url, headers=self.UA_HEADERS) as resp:
            assert resp.status == 200, f"{resp.status} {await resp.text()}"
            assert self.get_cookie(c.R357_PID).value, f"{c.R357_PID} is missing. This is unexpected."

    async def run_periodic_token_refresh(self):
        token_log.info(f"run_periodic_token_refresh")
        _24h_as_seconds = 24 * 60 * 60
        _5m_as_seconds = 5 * 60

        async def refresh_token_in_a_loop():
            token_log.debug('refresh_token_in_a_loop (wait until it\'s time)')
            if time() > self.get_cookie(c.R357_PID).expires - _24h_as_seconds:
                await self.init_r357_and_set_cookies_changed_if_needed(token_log)
            expires = self.get_cookie(c.TOKEN).expires
            expires_with_margin = expires - _5m_as_seconds
            while time() < expires_with_margin:
                if not self.is_playing_or_recoding:
                    return
                if self.session.closed:
                    return
                # token_log.debug(f"still time till {expires_with_margin} => sleeping 5")
                await asyncio.sleep(5)
            attempt = 0
            while True:
                attempt += 1
                token_log.debug(f"refresh_token_in_a_loop attempt {attempt}")
                if self.session.closed:
                    break
                await self.refresh_or_login(token_log)
                # query account to see if the new token works
                url = 'https://auth.r357.eu/api/account'
                token = self.get_cookie(c.TOKEN).value
                headers = self.UA_HEADERS | {c.AUTHORIZATION: f"{c.BEARER} {token}"}
                token_log.debug(f'query_account {headers=}')
                async with self.session.get(url, headers=headers) as resp:
                    if resp.status != 200:  # and self.is_playing_or_recoding:
                        msg = f"{resp.status} query_account; waiting {5 * attempt} sec before retrying"
                        token_log.debug(msg)
                        await asyncio.sleep(5 * attempt)
                    else:
                        token_log.debug(f"query_account {resp.status}")
                        break
            if self.is_playing_or_recoding:
                await refresh_token_in_a_loop()

        await refresh_token_in_a_loop()

    async def refresh_or_login(self, logger=macmarrum_log):
        # try to refresh the token before falling back to login
        is_to_login = False
        refresh_token_cookie = self.get_cookie(c.REFRESH_TOKEN)
        if not refresh_token_cookie.value:
            is_to_login = True
        elif time() > refresh_token_cookie.expires - 55 * 60:  # it's been more than 5 min since last refresh
            url = 'https://auth.r357.eu/api/auth/refresh'
            refresh_token = self.get_cookie(c.REFRESH_TOKEN).value
            headers = self.UA_HEADERS | self.ACCEPT_JSON_HEADERS
            _json = {c.REFRESHTOKEN: refresh_token}
            logger.debug(f"refresh token {headers=} {_json=}")
            async with self.session.post(url, headers=headers, json=_json) as resp:
                if resp.status == 200:
                    logger.debug(f"refresh token {resp.status}")
                    await self.update_and_persist_tokens_from_resp(resp, logger)
                else:
                    logger.debug(f"refresh token {resp.status}")
                    is_to_login = True
        if is_to_login:
            logger.debug('login')
            url = 'https://auth.r357.eu/api/auth/login'
            credentials = {c.EMAIL: self.conf[c.EMAIL], c.PASSWORD: self.conf[c.PASSWORD]}
            headers = self.UA_HEADERS | self.ACCEPT_JSON_HEADERS
            async with self.session.post(url, headers=headers, json=credentials) as resp:
                if resp.status == 200:
                    logger.debug(f"login {resp.status}")
                    await self.update_and_persist_tokens_from_resp(resp, logger)
                else:
                    logger.error(f"login {resp.status}")

    async def update_and_persist_tokens_from_resp(self, resp, logger=macmarrum_log):
        d = await resp.json()
        logger.debug(f"update_and_persist_tokens_from_resp resp.json()={d}")
        expires_int = int((datetime.now().replace(microsecond=0) + self.TOKEN_VALIDITY_DELTA).timestamp())
        expires_str = email.utils.formatdate(expires_int, usegmt=True)
        name_to_cookie = {
            c.TOKEN: mk_simple_cookie(c.TOKEN, d[c.ACCESS_TOKEN], expires_str),
            c.TOKEN_EXPIRES: mk_simple_cookie(c.TOKEN_EXPIRES, f"{expires_int}000", expires_str),
            c.REFRESH_TOKEN: mk_simple_cookie(c.REFRESH_TOKEN, d[c.REFRESHTOKEN], expires_str),
            c.REFRESH_TOKEN_EXPIRES: mk_simple_cookie(c.REFRESH_TOKEN_EXPIRES, f"{expires_int}000", expires_str),
        }
        url = yarl.URL.build(scheme='https', host='radio357.pl', path='/')
        self.session.cookie_jar.update_cookies(name_to_cookie[c.TOKEN], response_url=url)
        self.session.cookie_jar.update_cookies(name_to_cookie[c.TOKEN_EXPIRES], response_url=url)
        self.session.cookie_jar.update_cookies(name_to_cookie[c.REFRESH_TOKEN], response_url=url)
        self.session.cookie_jar.update_cookies(name_to_cookie[c.REFRESH_TOKEN_EXPIRES], response_url=url)
        self.is_cookies_changed = True

    async def handle_request_live(self, request: web.Request):
        queue, q = self.register_stream_consumer_to_get_queue()
        web_log.debug(f"handle_request_live queue #{q} - {request.remote} {request.method} {request.path} {request.version} {request.headers.get(c.USER_AGENT)}")
        server_resp = web.Response(content_type=c.AUDIO_AAC)
        server_resp.enable_chunked_encoding()
        await server_resp.prepare(request)
        buffer = b''
        if self.HANDLER_START_BUFFER_SEC:
            i = 0
            t = monotonic()
            while (duration := monotonic() - t) < self.HANDLER_START_BUFFER_SEC:
                buffer += await queue.get()
                i += 1
            web_log.debug(f"handle_request_live queue #{q} reached buffer in {duration:.2f} sec after reading {i} chunk(s)")
        while True:
            if buffer:
                chunk = buffer
                buffer = b''
            else:
                chunk = await queue.get()
            try:
                await server_resp.write(chunk)
            except (ConnectionResetError, Exception) as e:
                web_log.debug(f"{type(e).__name__}: {e}")
                self.unregister_stream_consumer(queue, q)
                break
        return server_resp

    async def handle_request_file_then_live(self, request: web.Request):
        web_log.debug(f"handle_request_rec - {request.remote} {request.method} {request.path} {request.version} {request.headers.get(c.USER_AGENT)}")
        server_resp = web.Response(content_type=c.AUDIO_AAC)
        server_resp.enable_chunked_encoding()
        await server_resp.prepare(request)
        is_file_path = self.file_path is not None
        if is_file_path:
            web_log.debug(f"handle_request_rec from {self.file_path.name}")
            async with aiofiles.open(self.file_path, 'rb') as fi:
                while chunk := await fi.read(self.ITER_REC_CHUNK_SIZE):
                    try:
                        await server_resp.write(chunk)
                    except (ConnectionResetError, Exception) as e:
                        web_log.debug(f"{type(e).__name__}: {e}")
                        return server_resp
        queue, q = self.register_stream_consumer_to_get_queue()
        if not is_file_path:
            web_log.warning(f"handle_request_rec - no file - was --record= used?")
        buffer = b''
        if not is_file_path and self.HANDLER_START_BUFFER_SEC:
            i = 0
            t = monotonic()
            while (duration := monotonic() - t) < self.HANDLER_START_BUFFER_SEC:
                buffer += await queue.get()
                i += 1
            web_log.debug(f"handle_request_rec queue #{q} reached buffer in {duration:.2f} sec after reading {i} chunk(s)")
        else:
            web_log.debug(f"handle_request_rec from queue #{q}")
        while True:
            if buffer:
                chunk = buffer
                buffer = b''
            else:
                chunk = await queue.get()
            try:
                await server_resp.write(chunk)
            except (ConnectionResetError, Exception) as e:
                web_log.debug(f"{type(e).__name__}: {e}")
                self.unregister_stream_consumer(queue, q)
                return server_resp


def mk_simple_cookie(name: str, value: str, expires: str):
    sc = SimpleCookie()
    sc[name] = value
    sc[name][c.EXPIRES] = expires
    sc[name][c.DOMAIN] = '.radio357.pl'
    sc[name][c.PATH] = '/'
    sc[name][c.SECURE] = True
    return sc


class MacmarrumCookie:
    """A wrapper for http.cookies.Morsel (returned by session.cookie_jar.__iter__),
    providing `value` and `expires` like http.cookiejar.Cookie"""

    def __init__(self, name: str, value: str, expires: int):
        self.name = name
        self.value = value
        self.expires = expires


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

    def mk_iter(self, _now: datetime = None, _debug=False):
        """_now and _debug are meant for testing and debugging"""
        if self.is_all_datetime:
            return self._mk_iterator_for_datetime_args(_now, _debug)
        elif self.is_every_hour:
            return self._mk_iterator_for_asterisk_arg0(_now, _debug)
        else:
            return self._mk_iterator_for_regular_args(_now, _debug)

    @property
    def count(self) -> int:
        """
        Runs the iterator and counts the number of iterations

        :return: count of iterations (files)
        """
        if self._count is None:
            FMT = self.FMT
            i = 0
            for e in self.mk_iter():
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

    def _mk_iterator_for_datetime_args(self, _now: datetime = None, _debug=False) -> SwitchFileIterator:
        # for testing, _now can be set to specific time
        start = end = _now or datetime.now(timezone.utc).astimezone()
        for file_num, dt in enumerate(self._switch_file_times, start=1):
            # new start is previous end, and real time for debugging
            start = end if not _debug else datetime.now(timezone.utc).astimezone()
            # end is the entry from the list
            end = dt
            duration = end - start
            yield file_num, start, end, duration

    def _mk_iterator_for_regular_args(self, _now: datetime = None, _debug=False) -> SwitchFileIterator:
        # for testing, _now can be set to specific time
        start = end = _now or datetime.now(timezone.utc).astimezone()
        file_num = 0
        h_m_s: tuple[int | None, int, int]
        for i, h_m_s in enumerate(self.parsed_switch_file_times):
            # new start is previous end, and real time for debugging
            start = end if not _debug else datetime.now(timezone.utc).astimezone()
            # end is the entry from the list
            h, m, s = h_m_s
            end = start.replace(hour=h, minute=m, second=s, microsecond=0)
            if end < start:
                end += self.DAYS1
            duration = end - start
            file_num += 1
            yield file_num, start, end, duration

    def _mk_iterator_for_asterisk_arg0(self, _now: datetime = None, _debug=False) -> SwitchFileIterator:
        # for testing, _now can be set to specific time
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
            # new start is previous end, and real time for debugging
            start = end if not _debug else datetime.now(timezone.utc).astimezone()
            # new end is start + 1h
            end = start + self.HOURS1
            # end is at the specified minutes and seconds of the hour
            end = end.replace(minute=m, second=s, microsecond=0)
            if end < start:
                end += self.DAYS1
            duration = end - start
            file_num += 1
            yield file_num, start, end, duration


def get_record_kwargs():
    for arg in sys.argv:
        if arg.startswith('--record='):
            args_as_json = arg.removeprefix('--record=')
            macmarrum_log.debug(f"{args_as_json=}")
            record_args = json.loads(args_as_json)
            macmarrum_log.debug(f"{record_args=}")
            return record_args
    return {}


def spawn_player_if_requested(macmarrum357, host, port):
    for arg in sys.argv:
        if arg.startswith('--play-with='):
            player = arg.removeprefix('--play-with=')
            player_cmd = shlex.split(player)
            break
        elif arg == '--play' and (mpv_command := macmarrum357.conf.get(c.MPV_COMMAND)):
            mpv_options = macmarrum357.conf.get(c.MPV_OPTIONS, [])
            player_cmd = [mpv_command, *mpv_options, f"http://{host}:{port}/live"]
            break
    else:  # no break
        player_cmd = None
    if player_cmd:
        macmarrum_log.info(f"spawn_player_if_requested {' '.join(quote(a) for a in player_cmd)}")
        subprocess.Popen(player_cmd)


async def macmarrum357_cleanup_ctx(app: web.Application):
    """https://docs.aiohttp.org/en/stable/web_advanced.html#aiohttp-web-cleanup-ctx
    a code before yield is an initialization stage (called on startup), a code after yield is executed on cleanup.
    """
    macmarrum357 = app['macmarrum357']
    kwargs = app['macmarrum357.run_client_kwargs']
    live_stream_client_task = asyncio.create_task(macmarrum357.run_client(**kwargs))
    yield
    live_stream_client_task.cancel()
    await live_stream_client_task


def on_web_app_shutdown(app):
    raise GracefulExit()


def main():
    """Run Macmarrum357 (live-stream client) and a live-stream server app"""
    # https://docs.aiohttp.org/en/stable/web_advanced.html#background-tasks
    configure_logging()
    record_kwargs = get_record_kwargs()
    live_stream_server_app = web.Application()
    macmarrum357 = Macmarrum357(live_stream_server_app)
    live_stream_server_app['macmarrum357'] = macmarrum357
    live_stream_server_app['macmarrum357.run_client_kwargs'] = record_kwargs
    live_stream_server_app.cleanup_ctx.append(macmarrum357_cleanup_ctx)
    live_stream_server_app.on_shutdown.append(on_web_app_shutdown)
    live_stream_server_app.add_routes([
        web.get('/live', macmarrum357.handle_request_live),
        web.get('/file-then-live', macmarrum357.handle_request_file_then_live)
    ])
    host = macmarrum357.conf.get(c.HOST, 'localhost')
    port = macmarrum357.conf.get(c.PORT, 8357)
    spawn_player_if_requested(macmarrum357, host, port)
    if macmarrum357.conf.get(c.NAMESERVERS) and os.name == 'nt':
        class MyPolicy(asyncio.DefaultEventLoopPolicy):

            def new_event_loop(self):
                selector = selectors.SelectSelector()
                return asyncio.SelectorEventLoop(selector)

        asyncio.set_event_loop_policy(MyPolicy())
    web.run_app(app=live_stream_server_app, host=host, port=port, print=web_log.debug)


if __name__ == '__main__':
    main()
