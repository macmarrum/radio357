from datetime import datetime, timedelta, timezone

from macmarrum357 import SwitchFileDateTime


def test_generator_for_asterisk_arg0_at_2330_till_0000():
    cron_time = datetime.now(timezone.utc).astimezone().replace(hour=23, minute=30, second=0, microsecond=100)
    entry = ['*:00', '00:00']
    _0000 = cron_time.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    expected = [
        (1, cron_time, _0000, _0000 - cron_time),
    ]
    actual = list(SwitchFileDateTime(entry)._mk_iterator_for_asterisk_arg0(_now=cron_time))
    assert actual == expected


def _test_generator_for_asterisk_arg0_at_215300_till_220015():
    cron_time = datetime.now(timezone.utc).astimezone().replace(hour=21, minute=53, second=0, microsecond=0)
    entry = ['*:55:15', '21:55:15']
    _215515 = cron_time.replace(hour=21, minute=55, second=15, microsecond=0)
    expected = [
        (1, cron_time, _215515, _215515 - cron_time),
    ]
    actual = list(SwitchFileDateTime(entry)._mk_iterator_for_asterisk_arg0(_now=cron_time))
    assert actual == expected


def test_generator_for_asterisk_arg0_at_2200_till_0200():
    cron_time = datetime.now(timezone.utc).astimezone().replace(hour=22, minute=0, second=0, microsecond=000)
    entry = ['*:00', '2:00']
    hours1 = timedelta(hours=1)
    _2300 = cron_time.replace(hour=23, minute=0, second=0, microsecond=0)
    _0000 = _2300 + hours1
    _0100 = _0000 + hours1
    _0200 = _0100 + hours1
    expected = [
        (1, cron_time, _2300, _2300 - cron_time),
        (2, _2300, _0000, hours1),
        (3, _0000, _0100, hours1),
        (4, _0100, _0200, hours1),
    ]
    actual = list(SwitchFileDateTime(entry)._mk_iterator_for_asterisk_arg0(_now=cron_time))
    assert actual == expected


def test_generator_for_asterisk_arg0_plus_3h():
    cron_time = datetime.now(timezone.utc).astimezone().replace(hour=6, minute=0, second=0, microsecond=100)
    entry = ['*:00', '9:00']
    _700 = cron_time.replace(hour=7, minute=0, second=0, microsecond=0)
    _800 = cron_time.replace(hour=8, minute=0, second=0, microsecond=0)
    _900 = cron_time.replace(hour=9, minute=0, second=0, microsecond=0)
    h1 = timedelta(hours=1)
    expected = [
        (1, cron_time, _700, _700 - cron_time),
        (2, _700, _800, h1),
        (3, _800, _900, h1),
    ]
    actual = list(SwitchFileDateTime(entry)._mk_iterator_for_asterisk_arg0(_now=cron_time))
    assert actual == expected


def test_int_sequence_parse():
    entry = ['7:07:17', '8:08:18', '9:09:19', 10, '11']
    expected = [
        (7, 7, 17),
        (8, 8, 18),
        (9, 9, 19),
        (10, 0, 0),
        (11, 0, 0),
    ]
    actual = SwitchFileDateTime(entry)._parse()
    assert actual == expected


def test_generator_for_regular_args_of_int_type():
    entry = [7, 8, 9]
    cron_time = datetime.now(timezone.utc).astimezone().replace(hour=6, minute=0, second=0, microsecond=100)
    _700 = cron_time.replace(hour=7, minute=0, second=0, microsecond=0)
    _800 = cron_time.replace(hour=8, minute=0, second=0, microsecond=0)
    _900 = cron_time.replace(hour=9, minute=0, second=0, microsecond=0)
    h1 = timedelta(hours=1)
    expected = [
        (1, cron_time, _700, _700 - cron_time),
        (2, _700, _800, h1),
        (3, _800, _900, h1),
    ]
    actual = list(SwitchFileDateTime(entry)._mk_iterator_for_regular_args(_now=cron_time))
    assert actual == expected


def test_generator_for_datetime_args():
    cron_time = datetime.now(timezone.utc).astimezone().replace(hour=6, minute=0, second=0, microsecond=100)
    _700 = cron_time.replace(hour=7, minute=0, second=0, microsecond=0)
    _800 = cron_time.replace(hour=8, minute=0, second=0, microsecond=0)
    _900 = cron_time.replace(hour=9, minute=0, second=0, microsecond=0)
    h1 = timedelta(hours=1)
    entry = [_700, _800, _900]
    expected = [
        (1, cron_time, _700, _700 - cron_time),
        (2, _700, _800, h1),
        (3, _800, _900, h1),
    ]
    actual = list(SwitchFileDateTime(entry)._mk_iterator_for_datetime_args(_now=cron_time))
    assert actual == expected
