#!/usr/bin/python3
# aiomacmarrum357 – an alternative CLI player/recorder for Radio357 patrons
# Copyright (C) 2024, 2025  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import email.utils
import json
import logging.config
import os
import re
import selectors
import shlex
import signal
import subprocess
import sys

try:
    import tomllib
except ImportError:
    import tomli as tomllib
import traceback
from collections.abc import Iterator
from datetime import datetime, timezone, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from time import time, monotonic, sleep
from typing import Callable

import aiofiles
import aiohttp
import tomli_w
import yarl
from aiohttp import AsyncResolver, CookieJar, web

UTF8 = 'UTF-8'

macmarrum_log = logging.getLogger('macmarrum357')
switch_log = logging.getLogger('macmarrum357.switch')
token_log = logging.getLogger('macmarrum357.token')
web_log = logging.getLogger('macmarrum357.web')
recorder_log = logging.getLogger('macmarrum357.recorder')


def get_appdata() -> Path:
    if os.name == 'nt':
        return Path(os.environ['APPDATA'])
    elif os.name == 'posix':
        return Path(os.environ.get('XDG_CONFIG_HOME', '~/.config')).expanduser()
    else:
        raise RuntimeError(f"unknown os.name: {os.name}")


macmarrum357_path = get_appdata() / 'macmarrum357'
macmarrum357_path.mkdir(exist_ok=True)
logging_toml_path = macmarrum357_path / 'logging.toml'

LOGGING_CONFIG_DEFAULT = {
    "version": 1,
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
            "formatter": "formatter"
        },
        "to_file": {
            "class": "logging.FileHandler",
            "filename": "macmarrum357.log",
            "encoding": "UTF-8",
            "formatter": "formatter"
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
    }
}


def configure_logging():
    try:
        with logging_toml_path.open('rb') as fi:
            dict_config = tomllib.load(fi)
    except FileNotFoundError:
        with logging_toml_path.open('wb') as fo:
            tomli_w.dump(LOGGING_CONFIG_DEFAULT, fo)
            dict_config = LOGGING_CONFIG_DEFAULT
    logging.config.dictConfig(dict_config)
    macmarrum_log.debug(f"configure_logging: {dict_config}")


def mk_filename(start: datetime, end: datetime, duration: timedelta, file_num: int, count: int, suffix: str):
    return f"{start.strftime('%Y-%m-%d,%a_%H')}{suffix}"


def quote(x):
    return shlex.quote(x)


class NoConsumers(RuntimeError):
    pass


StrIntDt = str | int | datetime
SwitchFileTimesType = list[StrIntDt] | tuple[StrIntDt]


class c:
    MACMARRUM357 = 'macmarrum357'
    MACMARRUM357_HOST = 'macmarrum357.host'
    MACMARRUM357_PORT = 'macmarrum357.port'
    LIVE_STREAM_URL = 'live_stream_url'
    LIVE_STREAM_LOCATION_REPLACEMENTS = 'live_stream_location_replacements'
    LOG_IN = 'log_in'
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
    PLAYER_ARGS = 'player_args'
    ACCEPT = 'Accept'
    APPLICATION_JSON = 'application/json'
    ACCEPT_ENCODING = 'Accept-Encoding'
    TRANSFER_ENCODING = 'Transfer-Encoding'
    IDENTITY = 'identity'
    LOCATION = 'location'
    AUDIO_AAC = 'audio/aac'
    CONTENT_TYPE = 'Content-Type'
    AUDIO_MPEG = 'audio/mpeg'
    APPLICATION_OCTET_STREAM = 'application/octet-stream'
    ICY_TITLE = 'icy_title'
    ICY_METADATA = 'Icy-MetaData'
    ICY_METAINT = 'icy-metaint'
    HOST = 'host'
    PORT = 'port'
    HANDLER_START_BUFFER_SEC = 'handler_start_buffer_sec'
    ZERO_AS_BYTES = b'\x00'
    FOREVER = 'forever'
    RECORD_ = '--record='
    PLAY_WITH_ = '--play-with='
    QUEUE0_BYTE_SIZE_LIMIT = 'queue0_byte_size_limit'
    QUEUE_BYTE_SIZE_LIMIT = 'queue_byte_size_limit'
    CONCURRENT_QUEUES_LIMIT = 'concurrent_queues_limit'
    RETRY_AFTER = 'Retry-After'
    TOO_MANY_REQUESTS_TEXT = 'Too many requests - the server has reached its maximum global connection capacity'


class Macmarrum357():
    r"""
    Plays the live stream of Radio 357, as a logged-in user, which skips start-up announcements.

    Logs in, gets cookies and uses them to receive the live stream.
    Makes the stream available locally via http so that it can be played,
    e.g. with **mpv**, Windows Media Player, etc.
    Optionally records the stream to one or several files, changing them at specified times.

    Play
    `python aiomacmarrum357.py --play`
    or
    `python aiomacmarrum357.py --play-with='["C:\\Program Files\\mpv\\mpv.exe", "--force-window=immediate", "--fs=no"]'`

    Record
    `python aiomacmarrum357.py --record='{"output_dir": "C:\\Users\\Mac\\r357", "switch_file_times": ["9:00", "12:00"]}'`

    The above command will record the live stream to files, changing them at the specified times, e.g. when started at 6:00, it will save two files:
    * 2024-09-23,Mon_06.aac - covering 6:00 to 9:00
    * 2024-09-23,Mon_09.aac - covering 9:00 to 12:00

    Record to files changed on the hour since the start until midnight, and spawn `aac-to-m4a` after each change
    `python aiomacmarrum357.py --record='{"output_dir": "C:\\Users\\Mac\\r357", "switch_file_times": ["*:00", "0:00"], "on_file_end": "aac-to-m4a"}'`

    Note: the values for options `--play=` and `--record=` are in JSON format

    Configuration

    Email and password for https://konto.radio357.pl must be specified in
    - %APPDATA%\macmarrum357\config.toml – on Windows
    or
    - ~/.config/macmarrum357/config.toml – on Unix

    The path to a player used with `--play` can be set in the same file, and player options:
    `player_args = ['C:\Program Files\mpv\mpv.exe', '--force-window=immediate', '--fs=no']`\
    as well as IP of the network interface and port where the stream will be served locally
    `host = '0.0.0.0`
    `port = 8357`
    The following can be set to enable icy-title in the /live stream, if your player supports it (**mpv** does):
    `icy_title = true`
    """
    STREAM = 'https://stream.radio357.pl/?s=www'
    REDCDN_LIVE_NO_PREROLL = 'https://r.dcs.redcdn.pl/sc/o2/radio357/live/radio357_pr.livx'
    DEFAULT_LOCATION_REPLACEMENTS = {REDCDN_LIVE_NO_PREROLL: REDCDN_LIVE_NO_PREROLL + '?preroll=0'}
    USER_AGENT = f"macmarrum/357 {aiohttp.http.SERVER_SOFTWARE}"
    UA_HEADERS = {c.USER_AGENT: USER_AGENT}
    AE_HEADERS = {c.ACCEPT: f"{c.AUDIO_AAC},{c.AUDIO_MPEG}", c.ACCEPT_ENCODING: c.IDENTITY}
    ACCEPT_JSON_HEADERS = {c.ACCEPT: c.APPLICATION_JSON}
    TOKEN_VALIDITY_DELTA = timedelta(minutes=60)
    ITER_CHUNKED_UP_TO_SIZE = 4 * 1024
    HANDLER_START_BUFFER_SEC = 0
    CONSUMER_CONTENT_TYPE_WAIT_MAX_ITER = 222
    CONSUMER_CONTENT_TYPE_WAIT_SEC = 0.1
    # with icy_title enabled, I can see icy_metaint: 16000
    # in the mp3 stream, 418 is the most common chunk size I've observed
    # in the aac stream, ~800
    QUEUE_LENGTH_LIMIT = 0  # limit on the count of chunks in a queue - 0 means unlimited
    DEFAULT_QUEUE0_BYTE_SIZE_LIMIT = 960_000  # (~60 sec) limit on size (in bytes) of all chunks in queue #0 - usually for writing to disk
    DEFAULT_QUEUE_BYTE_SIZE_LIMIT = 80_000  # (~5 sec) limit on size (in bytes) of all chunks in a subsequent queue (where # > 0)
    DEFAULT_CONCURRENT_QUEUES_LIMIT = 1_000  # limit on the number of concurrent consumers, post which status code 429 is sent
    RETRY_AFTER_HEADERS = {c.RETRY_AFTER: '300'}  # note: seconds as string - sent with status code 429
    QUEUE_EMPTY_TIMEOUT_SEC = 5.0  # when handling a http request, how long to wait for the next chunk before giving up
    ITER_FILE_CHUNK_SIZE = 8 * 1024
    ITER_FILE_WAIT_SECS_FOR_DATA = 1
    config_toml_path = macmarrum357_path / 'config.toml'
    aiohttp_cookiejar_pickle_path = macmarrum357_path / 'aiohttp_cookiejar.pickle'
    OUTPUT_FILE_MODE = 'ab'
    RX_TILDA_NUM = re.compile(r'(?<=~)\d+$')
    CONTENT_TYPE_TO_SUFFIX = {c.AUDIO_AAC: '.aac', c.AUDIO_MPEG: '.mp3', c.APPLICATION_OCTET_STREAM: '.bin'}
    _24H_AS_SECONDS = 24 * 60 * 60
    _5M_AS_SECONDS = 5 * 60

    def __init__(self, argv: list[str], recorder_kwargs: dict = None):
        self.init_datetime = datetime.now().astimezone()
        self.argv = argv
        self.recorder_kwargs = recorder_kwargs
        macmarrum_log.info('START Macmarrum357')
        self.validate_that_consumers_were_requested(argv)
        self.conf = {}
        self.load_config()
        self.should_log_in = self.conf.get(c.LOG_IN, True)
        self.is_cookies_changed = False
        self.is_client_running = False
        self.session: aiohttp.ClientSession = None
        self.location_replacements = self.conf.get(c.LIVE_STREAM_LOCATION_REPLACEMENTS, self.DEFAULT_LOCATION_REPLACEMENTS)
        self.queue_gen = ((ByteSizedAioQueue(self.QUEUE_LENGTH_LIMIT), q) for q in range(sys.maxsize))
        self._consumer_queues: list[tuple[ByteSizedAioQueue, int]] = []
        self.consumers_length = 0
        queue0_byte_size_limit = self.conf.get(c.QUEUE0_BYTE_SIZE_LIMIT, self.DEFAULT_QUEUE0_BYTE_SIZE_LIMIT)
        self.q0_to_byte_size_limit = {0: queue0_byte_size_limit}
        self.queue_byte_size_limit = self.conf.get(c.QUEUE_BYTE_SIZE_LIMIT, self.DEFAULT_QUEUE_BYTE_SIZE_LIMIT)
        self.concurrent_queues_limit = self.conf.get(c.CONCURRENT_QUEUES_LIMIT, self.DEFAULT_CONCURRENT_QUEUES_LIMIT)
        self.fo = None
        self.file_path: Path = None
        self.content_type = None
        self.icy_metaint = 0
        self.icy_title_bytes = b''
        self.icy_title_str = ''
        self.is_distribute_to_consumers_initial_run = True
        self.is_queue0_registered = False
        self.forever_qs = {}

    @staticmethod
    def validate_that_consumers_were_requested(argv: list[str]):
        for arg in argv:
            if arg.startswith(c.RECORD_) or arg == '--play' or arg.startswith(c.PLAY_WITH_):
                break
        else:  # no break
            message = 'no consumers requested: no --play or --play-with= or --record='
            macmarrum_log.critical(message)
            raise ValueError(message)

    def register_stream_consumer_to_get_queue(self, forever=False):
        if self.consumers_length == self.concurrent_queues_limit:
            macmarrum_log.info(f"register_stream_consumer => queue None - concurrent_queues_limit reached ({self.concurrent_queues_limit})")
            return None, None
        queue, q = next(self.queue_gen)
        self._consumer_queues.append((queue, q))
        self.consumers_length += 1
        if q == 0:
            self.is_queue0_registered = True
        if forever:
            self.forever_qs[q] = forever
        _forever = f" - {c.FOREVER}" if forever else ''
        macmarrum_log.debug(f"register_stream_consumer => queue #{q}{_forever}")
        return queue, q

    def unregister_stream_consumer(self, queue, q):
        macmarrum_log.debug(f"unregister_stream_consumer - queue #{q}")
        self._consumer_queues.remove((queue, q))
        self.consumers_length -= 1
        if q == 0:
            self.is_queue0_registered = False
        self.forever_qs.pop(q, None)

    def load_config(self):
        if not self.config_toml_path.exists():
            with self.config_toml_path.open('wb') as fo:
                conf = {c.LOG_IN: True, c.EMAIL: '', c.PASSWORD: '',
                        c.LIVE_STREAM_URL: self.STREAM,
                        # c.LIVE_STREAM_LOCATION_REPLACEMENTS: self.LOCATION_REPLACEMENTS,
                        c.ICY_TITLE: True,
                        c.PLAYER_ARGS: ['mpv', '--force-window=immediate', '--fs=no'],
                        # c.QUEUE0_BYTE_SIZE_LIMIT: self.DEFAULT_QUEUE0_BYTE_SIZE_LIMIT,
                        # c.QUEUE_BYTE_SIZE_LIMIT: self.DEFAULT_QUEUE_BYTE_SIZE_LIMIT,
                        # c.CONCURRENT_QUEUES_LIMIT: self.DEFAULT_CONCURRENT_QUEUES_LIMIT,
                        }
                tomli_w.dump(conf, fo)
        else:
            with self.config_toml_path.open('rb') as fi:
                conf = tomllib.load(fi)
            obfuscated_conf = conf.copy()
            for k, v in obfuscated_conf.items():
                if k in [c.EMAIL, c.PASSWORD] and v:
                    obfuscated_conf[k] = '*****'
            macmarrum_log.debug(f"load_config - {self.config_toml_path.name} - {obfuscated_conf}")
        if conf.get(c.LOG_IN, True) and (not conf.get(c.EMAIL) or not conf.get(c.PASSWORD)):
            macmarrum_log.critical(f"{self.config_toml_path} is missing email and/or password values")
            sys.exit(f"brak email i/lub password w {self.config_toml_path}")
        self.conf = conf

    async def run_client(self):
        self.is_client_running = True
        self.session = aiohttp.ClientSession(connector=self.mk_connector(), timeout=self.mk_timeout(), cookie_jar=self.mk_cookie_jar())
        if self.should_log_in:
            # await self.init_r357_and_set_cookies_changed_if_needed(macmarrum_log)
            await self.refresh_token_or_log_in_and_dump_cookies_if_needed(macmarrum_log)
            asyncio.create_task(self.run_periodic_token_refresh())
        resp = None
        i = 0
        chunk_num = 0
        headers = self.UA_HEADERS | self.AE_HEADERS
        if self.conf.get(c.ICY_TITLE) is True:
            headers |= {c.ICY_METADATA: '1'}
        while True:
            url = self.conf.get(c.LIVE_STREAM_URL, self.STREAM)
            try:
                macmarrum_log.debug(f"GET {url} - {headers}")
                while True:  # handle redirects
                    if resp and not resp.closed:
                        resp.close()
                    resp = await self.session.get(url, headers=headers, allow_redirects=False)
                    if resp.status in [301, 302, 303, 307, 308] and (location := resp.headers.get(c.LOCATION)):
                        macmarrum_log.debug(f"GET => {resp.status} - {c.LOCATION}: {location}")
                        if replacement := self.location_replacements.get(location):
                            macmarrum_log.debug(f"replace location with {replacement}")
                            location = replacement
                        url = location
                    else:
                        resp.raise_for_status()
                        self.content_type = resp.headers.get(c.CONTENT_TYPE, c.APPLICATION_OCTET_STREAM)
                        self.icy_metaint = int(resp.headers.get(c.ICY_METAINT, 0))
                        break
                macmarrum_log.debug(f"GET => {resp.status} - {dict(resp.headers)}")
                buffer = bytearray()
                min_buffer_size = self.icy_metaint + 1 + 255
                # see aiohttp.streams.StreamReader._read_nowait -> """Read not more than n bytes, or whole buffer if n == -1"""
                async for chunk in resp.content.iter_chunked(self.ITER_CHUNKED_UP_TO_SIZE):
                    if not (self.forever_qs or self.is_queue0_registered):
                        break
                    if self.icy_metaint:
                        buffer += chunk
                        if len(buffer) > min_buffer_size:
                            chunk = buffer[:self.icy_metaint]
                            del buffer[:self.icy_metaint]
                            icy_title_size = buffer[0] * 16
                            if icy_title_size:
                                self.icy_title_bytes = buffer[:1 + icy_title_size]
                                self.icy_title_str = self.icy_title_bytes.decode(UTF8)
                                del buffer[:1 + icy_title_size]
                            else:
                                del buffer[0]
                            await self.distribute_to_consumers(chunk, chunk_num)
                    else:
                        await self.distribute_to_consumers(chunk, chunk_num)
                    chunk_num += 1
            except NoConsumers:
                break
            except Exception as e:
                i += 1
                if i <= 1:
                    sec = 0  # 0 sec
                elif i <= 2:
                    sec = 1  # 0 + 2*1 = 2 sec since error
                elif i <= 6:
                    sec = 2  # 2 + 4*2 = 10 sec since error
                elif i <= 10:
                    sec = 5  # 10 + 4*5 = 30 sec since error
                elif i <= 69:
                    sec = 30  # 30 + 59*30 = 60 * 30 sec = 30 min since error
                elif i <= 99:
                    sec = 60  # 30 min + 30*60 = 60 min since error
                elif i <= 111:
                    sec = 300  # 60 min + 12 * 5*60 = 120 min (2h) since error
                elif i <= 117:
                    sec = 600  # 120 min + 6 * 10*60 = 180 min (3h) since error
                elif i <= 120:
                    sec = 1200  # 180 min + 3 * 20*60 = 240 min (4h) since error
                elif i <= 124:
                    sec = 1800  # 240 min + 4 * 30*60 = 600 min (6h) since error
                else:
                    sec = 3600  # after 6h since error, every 1h
                macmarrum_log.error(f"{type(e).__name__}: {e} - chunk #{chunk_num}")
                if i == 1 or sec >= 600:
                    macmarrum_log.error(traceback.format_exc())
                if sec:
                    macmarrum_log.debug(f"sleep {sec} sec before retrying")
                    await asyncio.sleep(sec)
            else:  # no exception
                # reset error counter
                i = 0
            if not (self.forever_qs or self.is_queue0_registered):
                break
        # end while
        macmarrum_log.info('stop client')
        if resp and not resp.closed:
            resp.close()
        if not self.session.closed:
            await self.session.close()
        self.is_client_running = False

    async def distribute_to_consumers(self, chunk, chunk_num):
        if self.is_distribute_to_consumers_initial_run:
            self.is_distribute_to_consumers_initial_run = False
            sec = 0.1
            for attempt in range(1, 6):
                if self.consumers_length:
                    break
                macmarrum_log.debug(f"distribute_to_consumers - initial run - sleep {sec} sec until a consumer comes online - attempt {attempt}")
                await asyncio.sleep(sec)
        if self.consumers_length:
            for queue, q in self._consumer_queues:
                try:
                    queue.put_nowait(chunk)
                except asyncio.QueueFull:
                    macmarrum_log.warning(f"distribute_to_consumers - queue #{q} - QueueFull - chunk #{chunk_num}")
                    self.unregister_stream_consumer(queue, q)
                byte_size_limit = self.q0_to_byte_size_limit.get(q, self.queue_byte_size_limit)  # get special limit for queue #0 or regular for other queues
                if queue.byte_size > byte_size_limit:  # QueueFull but in bytes, not length
                    macmarrum_log.warning(f"distribute_to_consumers - queue #{q} - byte_size_limit exceeded ({byte_size_limit}) - chunk #{chunk_num}")
                    self.unregister_stream_consumer(queue, q)
        else:
            macmarrum_log.debug(f"no consumers - chunk #{chunk_num}")
            macmarrum_log.info('no consumers')
            raise NoConsumers()

    def mk_connector(self):
        # https://github.com/netblue30/fdns/issues/47
        if nameservers := self.conf.get(c.NAMESERVERS):
            try:
                connector = aiohttp.TCPConnector(resolver=AsyncResolver(nameservers=nameservers))
            except Exception as e:
                macmarrum_log.error(f"{type(e).__name__} {e}")
                raise
        else:
            connector = None
        macmarrum_log.debug(f"mk_connector - use nameservers {nameservers}")
        return connector

    @staticmethod
    def mk_timeout():
        # https://github.com/aio-libs/aiohttp/issues/3203
        # https://stackoverflow.com/questions/61199544/dealing-with-aiohttp-session-get-timeout-issues-for-large-amout-of-requests
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=5, sock_read=5)
        macmarrum_log.debug(f"mk_timeout => {timeout}")
        return timeout

    def mk_cookie_jar(self):
        cookie_jar = CookieJar()
        exists = self.aiohttp_cookiejar_pickle_path.exists()
        macmarrum_log.debug(f"mk_cookie_jar - from {self.aiohttp_cookiejar_pickle_path.name}: {exists}")
        if exists:
            cookie_jar.load(self.aiohttp_cookiejar_pickle_path)
        return cookie_jar

    async def run_recorder(self, output_dir: str | Path = None, filename: str | Callable | None = None,
                           switch_file_times: SwitchFileTimesType = None,
                           on_file_start: str | Callable | None = None, on_file_end: str | Callable | None = None):
        try:
            queue, q = self.register_stream_consumer_to_get_queue()
            if output_dir is None:
                output_dir = Path().absolute()
            if filename is None:
                filename = mk_filename
            if switch_file_times is None:
                switch_file_times = [datetime.now().astimezone().replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)]
            switch_file_datetime = SwitchFileDateTime(switch_file_times)
            count = switch_file_datetime.count
            switch_file_datetime_iter = switch_file_datetime.mk_iter()
            start_output_file_args = (output_dir, filename, switch_file_datetime_iter, count)
            i = 0
            while self.content_type is None:
                if (i := i + 1) > self.CONSUMER_CONTENT_TYPE_WAIT_MAX_ITER:
                    recorder_log.debug(f"content_type still None - after {i} * {self.CONSUMER_CONTENT_TYPE_WAIT_SEC} sec - queue #{q}")
                    break
                await asyncio.sleep(self.CONSUMER_CONTENT_TYPE_WAIT_SEC)
            suffix = self.CONTENT_TYPE_TO_SUFFIX.get(self.content_type)
            self.file_path, self.fo, num, end_dt, duration = await self.start_output_file(*start_output_file_args, suffix)
            self.spawn_on_file_start_if_requested(on_file_start, self.file_path)
            recorder_log.info(f"{num}/{count} {duration} {self.file_path} - queue #{q}")
        except Exception as e:
            recorder_log.critical(f"run_recorder - {type(e).__name__} {e} - queue #{q}")
            raise
        try:
            while True:
                chunk = await queue.get()
                await self.fo.write(chunk)
                if end_dt and datetime.now(timezone.utc) >= end_dt:
                    await self.fo.close()
                    self.spawn_on_file_end_if_requested(on_file_end, self.file_path)
                    suffix = self.CONTENT_TYPE_TO_SUFFIX.get(self.content_type)
                    self.file_path, self.fo, num, end_dt, duration = await self.start_output_file(*start_output_file_args, suffix)
                    self.spawn_on_file_start_if_requested(on_file_start, self.file_path)
                    recorder_log.info(f"{num}/{count} {duration} {self.file_path} - queue #{q}")
        except Exception as e:
            # https://docs.python.org/3/library/exceptions.html#StopIteration
            if isinstance(e, RuntimeError) and isinstance(e.__cause__, StopIteration):
                recorder_log.debug(f"stop recorder: end of switch_file_times - queue #{q}")
            else:
                recorder_log.critical(f"{type(e).__name__}: {e} - queue #{q}")
        finally:
            self.unregister_stream_consumer(queue, q)
            if not self.fo.closed:
                recorder_log.debug(f"close self.fo - queue #{q}")
                await self.fo.close()

    @classmethod
    async def start_output_file(cls, output_dir, filename, switch_file_datetime_iterator: Iterator, count: int, suffix: str):
        file_num, start, end, duration = next(switch_file_datetime_iterator)
        output_path = Path(output_dir) / filename(start=start, end=end, duration=duration, file_num=file_num,
                                                  count=count, suffix=suffix) if callable(filename) else filename
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
            recorder_log.warning(f"change filename to {new_stem}{output_path.suffix}: file exists {old_path}")
            is_filename_changed = True
        if not is_filename_changed and 'a' in cls.OUTPUT_FILE_MODE and output_path.exists():
            recorder_log.warning(f"append to an exiting file - {output_path}")
        fo = await aiofiles.open(output_path, cls.OUTPUT_FILE_MODE)
        return output_path, fo, file_num, end, duration

    @staticmethod
    def spawn_on_file_start_if_requested(on_file_start, path):
        if on_file_start is not None:
            if callable(on_file_start):
                on_file_start(path)
            else:
                args = [on_file_start, str(path)]
                recorder_log.debug(f"spawn_on_file_start - {' '.join(quote(a) for a in args)}")
                subprocess.Popen(args)

    @staticmethod
    def spawn_on_file_end_if_requested(on_file_end, path):
        if on_file_end is not None:
            if callable(on_file_end):
                on_file_end(path)
            else:
                args = [on_file_end, str(path)]
                recorder_log.info(f"spawn_on_file_end - {' '.join(quote(a) for a in args)}")
                subprocess.Popen(args)

    async def init_r357_and_set_cookies_changed_if_needed(self, logger: logging.Logger):
        """Doesn't dump cookies directly. Only signals the need.
        Cookies will be dumped with the next refresh_token_or_log_in_and_dump_cookies_if_needed"""
        r357_pid = self.get_cookie(c.R357_PID)
        await self.init_r357(logger)
        r357_pid_new = self.get_cookie(c.R357_PID)
        if r357_pid_new.value != r357_pid.value or r357_pid_new.expires != r357_pid.expires:
            self.is_cookies_changed = True
        old_expires = datetime.fromtimestamp(r357_pid.expires, timezone.utc).astimezone().isoformat(sep=' ')
        new_expires = datetime.fromtimestamp(r357_pid_new.expires, timezone.utc).astimezone().isoformat(sep=' ')
        logger.debug(f"init_r357_and_set_cookies_changed_if_needed => {self.is_cookies_changed} - expires {{old: {old_expires}, new: {new_expires}}}")

    def get_cookie(self, name, domain=None):
        parse_date = aiohttp.cookiejar.CookieJar._parse_date
        # initial session has no cookies, so ignore
        if isinstance(self.session.cookie_jar, CookieJar):
            # macmarrum_log.debug(f"{self.session.cookie_jar._cookies=}")
            for morsel in self.session.cookie_jar:
                if domain and morsel[c.DOMAIN] != domain:
                    continue
                if morsel.key == name:
                    return MacmarrumCookie(name, morsel.value, parse_date(morsel[c.EXPIRES]))
        return MacmarrumCookie(name, '', 0)

    async def init_r357(self, logger: logging.Logger):
        url = 'https://checkout.radio357.pl/user/init/'
        headers = self.UA_HEADERS
        logger.debug(f"init_r357 - {url} - {headers}")
        async with self.session.get(url, headers=headers) as resp:
            logger.debug(f"init_r357 => {resp.status}")
            resp.raise_for_status()
            if not self.get_cookie(c.R357_PID).value:
                msg = f"init_r357 - cookie {c.R357_PID} is missing"
                logger.critical(msg)
                raise RuntimeError(msg)

    async def run_periodic_token_refresh(self):
        token_log.info('run_periodic_token_refresh')

        async def refresh_token_in_a_loop():
            token_log.debug('refresh_token_in_a_loop - sleep until it\'s time')
            if time() > self.get_cookie(c.R357_PID).expires - self._24H_AS_SECONDS:
                await self.init_r357_and_set_cookies_changed_if_needed(token_log)
            expires = self.get_cookie(c.TOKEN).expires
            expires_with_margin = expires - self._5M_AS_SECONDS
            while time() < expires_with_margin:
                if not self.is_client_running:
                    return
                if self.session.closed:
                    return
                # token_log.debug(f"still time till {expires_with_margin} => sleeping 5")
                await asyncio.sleep(5)
            attempt = 0
            while True:
                attempt += 1
                token_log.debug(f"refresh_token_in_a_loop - attempt {attempt}")
                if self.session.closed:
                    break
                await self.refresh_token_or_log_in_and_dump_cookies_if_needed(token_log)
                # query account to see if the new token works
                url = 'https://auth.r357.eu/api/account'
                token = self.get_cookie(c.TOKEN).value
                headers = self.UA_HEADERS | {c.AUTHORIZATION: f"{c.BEARER} {token}"}
                obfuscated_headers = self.UA_HEADERS | {c.AUTHORIZATION: f"{c.BEARER} $token"}
                token_log.debug(f"query_account - {url} - {obfuscated_headers}")
                async with self.session.get(url, headers=headers) as resp:
                    if resp.status != 200:  # and self.is_playing_or_recoding:
                        msg = f"query_account => {resp.status} - sleep {5 * attempt} sec before retrying"
                        token_log.debug(msg)
                        await asyncio.sleep(5 * attempt)
                    else:
                        token_log.debug(f"query_account => {resp.status}")
                        break
            if self.is_client_running:
                await refresh_token_in_a_loop()

        await refresh_token_in_a_loop()

    async def refresh_token_or_log_in_and_dump_cookies_if_needed(self, logger: logging.Logger):
        logger.debug('refresh_token_or_log_in_and_dump_cookies_if_needed')
        # try to refresh the token before falling back to logging in
        is_to_log_in = False
        refresh_token_cookie = self.get_cookie(c.REFRESH_TOKEN)
        if not refresh_token_cookie.value:  # no cookie - log in
            is_to_log_in = True
        elif time() >= (expires_with_margin := refresh_token_cookie.expires - self._5M_AS_SECONDS):  # it's been at least 55 min since last refresh
            is_to_log_in = not await self.refresh_token(logger)
        if is_to_log_in:
            await self.log_in(logger)
        self.dump_cookies_if_changed(logger)

    async def refresh_token(self, logger: logging.Logger):
        url = 'https://auth.r357.eu/api/auth/refresh'
        headers = self.UA_HEADERS | self.ACCEPT_JSON_HEADERS
        _json = {c.REFRESHTOKEN: self.get_cookie(c.REFRESH_TOKEN).value}
        logger.debug(f"refresh_token - {url} - {headers} - json=$refresh_token")
        async with self.session.post(url, headers=headers, json=_json) as resp:
            logger.debug(f"refresh_token => {resp.status}")
            if resp.status == 200:
                await self.update_and_persist_tokens_from_resp(resp, logger)
                return True
            else:
                return False

    async def log_in(self, logger: logging.Logger):
        url = 'https://auth.r357.eu/api/auth/login'
        credentials = {c.EMAIL: self.conf[c.EMAIL], c.PASSWORD: self.conf[c.PASSWORD]}
        headers = self.UA_HEADERS | self.ACCEPT_JSON_HEADERS
        logger.debug(f"log_in - {url} - {headers} - json=$credentials")
        async with self.session.post(url, headers=headers, json=credentials) as resp:
            logger.debug(f"log_in => {resp.status}")
            if resp.status == 200:
                await self.update_and_persist_tokens_from_resp(resp, logger)
                return True
            else:
                return False

    async def update_and_persist_tokens_from_resp(self, resp, logger: logging.Logger):
        d = await resp.json()
        logger.debug('update_and_persist_tokens_from_resp - $json')
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

    def dump_cookies_if_changed(self, logger: logging.Logger):
        logger.debug(f"dump_cookies_if_changed: {self.is_cookies_changed}")
        if not self.is_cookies_changed:
            return
        cookie_jar = self.session.cookie_jar
        if isinstance(cookie_jar, CookieJar):
            cookie_jar.save(self.aiohttp_cookiejar_pickle_path)
            self.is_cookies_changed = False
            # for morsel in cookie_jar:
            #     macmarrum_log.debug(f"dump_cookies_if_changed - {morsel.OutputString().replace(morsel.value, '*****')}")
        else:
            macmarrum_log.debug(f"dump_cookies_if_changed - unexpected cookie_jar type: {cookie_jar.__class__.__name__}")

    async def run_chunk_sizes_collector(self):
        path = None
        for argv in self.argv:
            if argv.startswith('--chunk-sizes-file='):
                path = Path(argv.split('=')[1])
                break
        if not path:
            return
        while not self.consumers_length:
            await asyncio.sleep(1)
        queue, q = self.register_stream_consumer_to_get_queue()
        macmarrum_log.debug(f"run_chunk_sizes_collector - queue #{q} -> {path}")
        async with aiofiles.open(path, 'w', encoding='L1') as fo:
            while self.is_client_running:
                try:
                    chunk = await asyncio.wait_for(queue.get(), self.QUEUE_EMPTY_TIMEOUT_SEC)
                    await fo.write(f"{len(chunk)}\n")
                except (TimeoutError, asyncio.CancelledError, IOError) as e:
                    macmarrum_log.debug(f"run_chunk_sizes_collector - queue #{q} - {type(e).__name__} {e}")
                    self.unregister_stream_consumer(queue, q)
                    break

    async def handle_request_live(self, request: web.Request):
        handle_request = 'handle_request_live'
        forever = c.FOREVER in request.query
        _forever = f" - {c.FOREVER}" if forever else ''
        web_log_request(f"{handle_request}{_forever}", request)
        queue, q = self.register_stream_consumer_to_get_queue(forever=forever)
        if not queue:
            web_log.debug(f"{handle_request} => 429 Too Many Requests (globally)")
            return web.Response(status=429, headers=self.RETRY_AFTER_HEADERS, text=c.TOO_MANY_REQUESTS_TEXT)
        i = 0
        while self.content_type is None:
            if (i := i + 1) > self.CONSUMER_CONTENT_TYPE_WAIT_MAX_ITER:
                web_log.debug(f"{handle_request} - queue #{q} - content_type still None - after {self.CONSUMER_CONTENT_TYPE_WAIT_MAX_ITER} * {self.CONSUMER_CONTENT_TYPE_WAIT_SEC} sec")
                break
            await asyncio.sleep(self.CONSUMER_CONTENT_TYPE_WAIT_SEC)
        should_serve_icy_title = self.icy_metaint and request.headers.get(c.ICY_METADATA) == '1'
        if should_serve_icy_title:
            headers = {c.ICY_METAINT: str(self.icy_metaint)}
        else:
            headers = None
        web_log.debug(f"{handle_request} - queue #{q} => respond {c.CONTENT_TYPE}: {self.content_type}, {c.TRANSFER_ENCODING}: chunked, headers: {headers}")
        server_resp = web.Response(content_type=self.content_type, headers=headers)
        server_resp.enable_chunked_encoding()
        await server_resp.prepare(request)
        buffer = bytearray()
        handler_start_buffer_sec = self.conf.get(c.HANDLER_START_BUFFER_SEC, self.HANDLER_START_BUFFER_SEC)
        if handler_start_buffer_sec:
            i = 0
            t = monotonic()
            while (duration := monotonic() - t) < handler_start_buffer_sec:
                buffer += await queue.get()
                i += 1
            web_log.debug(f"{handle_request} - queue #{q} - reached buffer in {duration:.2f} sec after reading {i} chunk(s)")
        icy_title_bytes = b''
        icy_title_str_to_count = {}
        while True:
            if buffer:
                chunk = buffer
                buffer = b''
            else:
                # get next chunk from queue, with timeout
                try:
                    chunk = await asyncio.wait_for(queue.get(), self.QUEUE_EMPTY_TIMEOUT_SEC)
                except asyncio.TimeoutError:
                    web_log.debug(f"{handle_request} - queue #{q} - QUEUE_EMPTY_TIMEOUT_SEC exceeded")
                    self.unregister_stream_consumer(queue, q)
                    break
                except asyncio.CancelledError:
                    web_log.debug(f"{handle_request} - queue #{q} - CancelledError during wait_for queue.get()")
                    self.unregister_stream_consumer(queue, q)
                    break
            if should_serve_icy_title:
                # serve icy-title twice
                if (count := icy_title_str_to_count.get(self.icy_title_str, 0)) <= 2:
                    icy_title_str_to_count[self.icy_title_str] = count + 1
                    icy_title_bytes = self.icy_title_bytes
                else:
                    del icy_title_str_to_count[self.icy_title_str]
                    icy_title_bytes = c.ZERO_AS_BYTES
            try:
                await server_resp.write(chunk)
                if should_serve_icy_title:
                    await server_resp.write(icy_title_bytes)
            except Exception as e:  # incl. ConnectionResetError
                web_log.debug(f"{handle_request} - queue #{q} - {type(e).__name__}: {e}")
                self.unregister_stream_consumer(queue, q)
                break
        web_log.debug(f"{handle_request} - queue #{q}{_forever} - finish")
        return server_resp

    async def handle_request_file_then_live(self, request: web.Request):
        handle_request = 'handle_request_file_then_live'
        forever = c.FOREVER in request.query
        _forever = f" - {c.FOREVER}" if forever else ''
        web_log_request(f"{handle_request}{_forever}", request)
        i = 0
        while self.content_type is None:
            if (i := i + 1) > self.CONSUMER_CONTENT_TYPE_WAIT_MAX_ITER:
                web_log.debug(f"{handle_request} - content_type still None - after {self.CONSUMER_CONTENT_TYPE_WAIT_MAX_ITER} * {self.CONSUMER_CONTENT_TYPE_WAIT_SEC} sec")
                break
            await asyncio.sleep(self.CONSUMER_CONTENT_TYPE_WAIT_SEC)
        web_log.debug(f"{handle_request} => respond {c.CONTENT_TYPE}: {self.content_type}, {c.TRANSFER_ENCODING}: chunked")
        server_resp = web.Response(content_type=self.content_type)
        server_resp.enable_chunked_encoding()
        await server_resp.prepare(request)
        is_file_path = self.file_path is not None
        if is_file_path:
            web_log.debug(f"{handle_request} - {self.file_path.name}")
            async with aiofiles.open(self.file_path, 'rb') as fi:
                while chunk := await fi.read(self.ITER_FILE_CHUNK_SIZE):
                    try:
                        await server_resp.write(chunk)
                    except Exception as e:  # incl. ConnectionResetError
                        web_log.debug(f"{handle_request} - {self.file_path.name} - {type(e).__name__}: {e}")
                        return server_resp
        else:
            web_log.warning(f"{handle_request} - no file - was --record= used?")
        queue, q = self.register_stream_consumer_to_get_queue(forever=forever)
        if not queue:
            web_log.debug(f"{handle_request} => 429 Too Many Requests (globally)")
            return web.Response(status=429, headers=self.RETRY_AFTER_HEADERS, text=c.TOO_MANY_REQUESTS_TEXT)
        buffer = b''
        handler_start_buffer_sec = self.conf.get(c.HANDLER_START_BUFFER_SEC, self.HANDLER_START_BUFFER_SEC)
        if not is_file_path and handler_start_buffer_sec:
            i = 0
            t = monotonic()
            while (duration := monotonic() - t) < handler_start_buffer_sec:
                buffer += await queue.get()
                i += 1
            web_log.debug(f"{handle_request} - queue #{q} reached buffer in {duration:.2f} sec after reading {i} chunk(s)")
        else:
            web_log.debug(f"{handle_request} - queue #{q}{_forever}")
        while True:
            if buffer:
                chunk = buffer
                buffer = b''
            else:
                # get next chunk from queue, with timeout
                try:
                    chunk = await asyncio.wait_for(queue.get(), self.QUEUE_EMPTY_TIMEOUT_SEC)
                except asyncio.TimeoutError:
                    web_log.debug(f"{handle_request} - queue #{q} - QUEUE_EMPTY_TIMEOUT_SEC exceeded")
                    self.unregister_stream_consumer(queue, q)
                    break
            try:
                await server_resp.write(chunk)
            except Exception as e:  # incl. ConnectionResetError
                web_log.debug(f"{handle_request} - queue #{q} - {type(e).__name__}: {e}")
                self.unregister_stream_consumer(queue, q)
                break
        web_log.debug(f"{handle_request} - queue #{q}{_forever} - finish")
        return server_resp


def web_log_request(prefix: str, request: web.Request):
    v = request.version
    web_log.info(f"{prefix} - {request.remote} {request.method} {request.path_qs} HTTP/{v.major}.{v.minor} {request.headers.get(c.USER_AGENT)}")


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

    def __init__(self, switch_file_times: SwitchFileTimesType):
        self._is_all_datetime = None
        self._switch_file_times = switch_file_times
        sft_for_log = [e.strftime(self.FMT) for e in switch_file_times] if self.is_all_datetime else switch_file_times
        recorder_log.debug(f"SwitchFileDateTime switch_file_times={sft_for_log}")
        self._is_every_hour = None
        self._validate()
        self._parsed_switch_file_times = None
        self._count = None

    def _validate(self):
        switch_file_times = self._switch_file_times
        switch_file_times_len = len(switch_file_times)
        if switch_file_times_len == 0:
            msg = f"expected size > 0, got {switch_file_times_len=}"
            switch_log.critical(msg)
            raise ValueError(msg)
        if self.is_every_hour:
            if switch_file_times_len != 2:
                msg = f"expected size == 2, got {switch_file_times_len=}"
                switch_log.critical(msg)
                raise ValueError(msg)
        if not (self.is_all_datetime or all(isinstance(e, int) or self.RX_H_MM_SS.match(e) for e in switch_file_times)):
            msg = 'not ( self.is_all_datetime or all(isinstance(e, int) or self.RX_H_MM_SS.match(e) for e in switch_file_times) )'
            switch_log.critical(msg)
            raise ValueError(msg)
        self.make_switch_file_times_aware_if_needed()

    def make_switch_file_times_aware_if_needed(self):
        if self.is_all_datetime:
            for i, dt in enumerate(self._switch_file_times):
                if dt.tzinfo is None:
                    self._switch_file_times[i] = dt.astimezone()

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
                recorder_log.debug(f"SwitchFileDateTime {e[0]}: [{e[1].strftime(FMT)}, {e[2].strftime(FMT)}]")
            self._count = i
        return self._count

    def _parse(self):
        if self.is_all_datetime:
            msg = 'is_all_datetime - nothing to parse'
            switch_log.critical(msg)
            raise TypeError(msg)
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
        recorder_log.debug(f"SwitchFileDateTime {parsed_switch_file_times=}")
        return parsed_switch_file_times

    def _mk_iterator_for_datetime_args(self, _now: datetime = None, _debug=False) -> SwitchFileIterator:
        # for testing, _now can be set to specific time
        end = _now or datetime.now().astimezone()
        for file_num, dt in enumerate(self._switch_file_times, start=1):
            # new start is previous end, and real time for debugging
            start = end if not _debug else datetime.now().astimezone()
            # end is the entry from the list
            end = dt
            duration = end - start
            yield file_num, start, end, duration

    def _mk_iterator_for_regular_args(self, _now: datetime = None, _debug=False) -> SwitchFileIterator:
        # for testing, _now can be set to specific time
        end = _now or datetime.now().astimezone()
        file_num = 0
        h_m_s: tuple[int | None, int, int]
        for i, h_m_s in enumerate(self.parsed_switch_file_times):
            # new start is previous end, and real time for debugging
            start = end if not _debug else datetime.now().astimezone()
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
        start = _now or datetime.now().astimezone()
        _, m, s = self.parsed_switch_file_times[0]
        final_h, final_m, final_s = self.parsed_switch_file_times[1]
        final_end = start.replace(hour=final_h, minute=final_m, second=final_s, microsecond=0)
        if final_end < start:
            final_end += self.DAYS1
        end = (start + self.HOURS1).replace(minute=m, second=s, microsecond=0)
        file_num = 1
        yield file_num, start, end, end - start
        while end < final_end:
            # new start is previous end, and real time for debugging
            start = end if not _debug else datetime.now().astimezone()
            # new end is start + 1h
            end = start + self.HOURS1
            # end is at the specified minutes and seconds of the hour
            end = end.replace(minute=m, second=s, microsecond=0)
            if end < start:
                end += self.DAYS1
            duration = end - start
            file_num += 1
            yield file_num, start, end, duration


class ByteSizedAioQueue(asyncio.Queue):
    """Tracks total size of all chunks in the queue, using sys.getsizeof by default"""

    def __init__(self, maxsize=0, chunk_size_calculator: Callable = None):
        super().__init__(maxsize=maxsize)
        self._chunk_size_calculator = chunk_size_calculator if chunk_size_calculator else sys.getsizeof
        self._byte_size = 0

    def put_nowait(self, chunk):
        super().put_nowait(chunk)
        chunk_size = self._chunk_size_calculator(chunk)
        self._byte_size += chunk_size

    async def get(self):
        chunk = await super().get()
        chunk_size = self._chunk_size_calculator(chunk)
        self._byte_size -= chunk_size
        return chunk

    @property
    def byte_size(self):
        return self._byte_size


def sleep_if_requested(argv: list[str]):
    for arg in argv:
        if arg.startswith('--sleep='):
            sec = float(arg.removeprefix('--sleep='))
            macmarrum_log.info(f"sleep {sec:.1f} second(s)")
            sleep(sec)
            return


class MyPolicy(asyncio.DefaultEventLoopPolicy):
    def new_event_loop(self):
        selector = selectors.SelectSelector()
        return asyncio.SelectorEventLoop(selector)


def get_recorder_kwargs(argv: list[str]):
    for arg in argv:
        if arg.startswith(c.RECORD_):
            args_as_json = arg.removeprefix(c.RECORD_)
            recorder_log.debug(f"{args_as_json=}")
            record_args = json.loads(args_as_json)
            recorder_log.debug(f"{record_args=}")
            return record_args
    return {}


def spawn_player_if_requested(macmarrum357, host, port):
    for arg in macmarrum357.argv:
        if arg.startswith(c.PLAY_WITH_):
            player = arg.removeprefix(c.PLAY_WITH_)
            player_args = json.loads(player)
            if not isinstance(player_args, list):
                player_args = [player_args]
            break
        elif arg == '--play':
            if not (player_args := macmarrum357.conf.get(c.PLAYER_ARGS)):
                macmarrum_log.error(f"spawn_player - `--play` requested but no {c.PLAYER_ARGS} in config")
            break
    else:  # no break
        player_args = None
    if player_args:
        player_args.append(f"http://{host}:{port}/live")
        macmarrum_log.info(f"spawn_player - {' '.join(quote(a) for a in player_args)}")
        subprocess.Popen(player_args)


async def shutdown_app_when_no_consumers(macmarrum357: Macmarrum357):
    while not macmarrum357.consumers_length:
        # web_log.debug(f"shutdown_app_when_no_consumers - wait for any consumer to appear")
        await asyncio.sleep(1)
    # web_log.debug(f"shutdown_app_when_no_consumers - wait for all consumers to exit")
    while macmarrum357.consumers_length:
        await asyncio.sleep(1)
    web_log.debug('shutdown_app_when_no_consumers - send SIGTERM')
    web_log.info('STOP Macmarrum357')
    # https://github.com/aio-libs/aiohttp/issues/2950
    # web.run_app -> AppRunner(BaseRunner) reacts on SIGINT, SIGTERM (raising GracefulExit)
    signal.raise_signal(signal.SIGTERM)


async def macmarrum357_cleanup_ctx(app: web.Application):
    """https://docs.aiohttp.org/en/stable/web_advanced.html#aiohttp-web-cleanup-ctx
    a code before yield is an initialization stage (called on startup), a code after yield is executed on cleanup.
    """
    macmarrum357: Macmarrum357 = app[c.MACMARRUM357]
    live_stream_client_task = asyncio.create_task(macmarrum357.run_client())
    if recorder_kwargs := macmarrum357.recorder_kwargs:
        live_stream_recorder_task = asyncio.create_task(macmarrum357.run_recorder(**recorder_kwargs))
    host = app[c.MACMARRUM357_HOST]
    port = app[c.MACMARRUM357_PORT]
    spawn_player_if_requested(macmarrum357, host, port)
    shutdown_task = asyncio.create_task(shutdown_app_when_no_consumers(macmarrum357))
    chunk_sizes_task = asyncio.create_task(macmarrum357.run_chunk_sizes_collector())
    yield
    chunk_sizes_task.cancel()
    if recorder_kwargs:
        live_stream_recorder_task.cancel()
    live_stream_client_task.cancel()
    shutdown_task.cancel()


def web_log_info_splitlines(message: str):
    for line in message.splitlines(keepends=False):
        web_log.info(line)


def main(argv: list[str] = None):
    """Run Macmarrum357 (live-stream client) and a live-stream server app"""
    # https://docs.aiohttp.org/en/stable/web_advanced.html#background-tasks
    if argv is None:
        argv = sys.argv
    configure_logging()
    sleep_if_requested(argv)
    recorder_kwargs = get_recorder_kwargs(argv)
    macmarrum357 = Macmarrum357(argv, recorder_kwargs)
    live_stream_server_app = web.Application()
    live_stream_server_app[c.MACMARRUM357] = macmarrum357
    live_stream_server_app.cleanup_ctx.append(macmarrum357_cleanup_ctx)
    live_stream_server_app.add_routes([
        web.get('/live', macmarrum357.handle_request_live),
        web.get('/file-then-live', macmarrum357.handle_request_file_then_live)
    ])
    host = macmarrum357.conf.get(c.HOST, 'localhost')
    port = macmarrum357.conf.get(c.PORT, 8357)
    live_stream_server_app[c.MACMARRUM357_HOST] = host
    live_stream_server_app[c.MACMARRUM357_PORT] = port
    if macmarrum357.conf.get(c.NAMESERVERS) and os.name == 'nt':
        asyncio.set_event_loop_policy(MyPolicy())
    web.run_app(app=live_stream_server_app, host=host, port=port, print=web_log_info_splitlines)


if __name__ == '__main__':
    main()
