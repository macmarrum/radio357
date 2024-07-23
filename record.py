#!/usr/bin/python3
from datetime import timedelta, datetime
from pathlib import Path

from macmarrum357 import Macmarrum357

me = Path(__file__)


def mk_filename(start: datetime, end: datetime, duration: timedelta, file_num: int, count: int):
    return f"{start.strftime('%Y-%m-%d,%a_%H:%M:%S.%f')}.aac"


output_dir = Path('/home/m/tmp/macmarrum357')
switch_file_at = ('*', '00:00')
Macmarrum357().start_recording(output_dir, mk_filename, switch_file_at, player='mpvstream')
