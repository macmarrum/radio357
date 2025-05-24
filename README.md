# aplikacja radio357

## aiomacmarrum357 – alternatywny odtwarzacz i/lub nagrywarka Radia 357 dla patronów, działający z wiersza poleceń

Odtwarza i/lub nagrywa Radio 357 na żywo, jako zalogowany użytkownik, z pominięciem komunikatu startowego.

Loguje użytkownika, pobiera ciasteczka i używa ich do odbierania strumienia na żywo.
Pobierany strumień udostępnia lokalnie przez HTTP dla potrzeb odtwarzania, np. przy użyciu **mpv**, Windows Media Player, itp.
Opcjonalnie nagrywa strumień do jednego lub kilku plików, zmieniając je o określonych porach.

> Przykładowo, chcę słuchać audycji niedzielnej o 20:00, ale często spóźniam się i zaczynam około 20:30.\
> Włączam zatem nagrywanie audycji, a o 20:30 uruchamiam odtwarzanie od początku nagrywanego pliku.
> 1. Dodaję polecenie do Harmonogramu Zadań Windows ([instrukcje](https://pl.101-help.com/jak-utworzyc-automatyczne-zadanie-za-pomoca-harmonogramu-zadan-w-systemie-windows-11-10-6868e186b0/)) `"C:\Program Files\Python311\python.exe" "C:\Users\Mac\aiomacmarrum357.py" --record='{"output_dir": "C:\\Users\\Mac\\radio357", "switch_file_times": ["22:00"]}'`
> 2. Między 20:00 a 22:00 uruchamiam odtwarzanie http://localhost:8357/file-then-live, np. w **mpv** albo VLC.

Odtwarzanie na żywo\
`python aiomacmarrum357.py --play`\
lub\
`python aiomacmarrum357.py --play-with='["C:\\Program Files\\mpv\\mpv.exe", "--force-window=immediate", "--fs=no"]'`

Nagrywanie\
`python aiomacmarrum357.py --record='{"output_dir": "C:\\Users\\Mac\\radio357", "switch_file_times": ["9:00", "12:00"]}'`

Powyższe polecenie zapisze program na żywo do plików, zmieniając je o określonych porach;
w przypadku uruchomienia o 6:00 zapisze dwa pliki:
* 2024-09-23,Mon_06.aac - obejmujący audycję od 6:00 do 9:00
* 2024-09-23,Mon_09.aac - obejmujący audycję od 9:00 do 12:00

***Wskazówka**: wartości dla opcji `--play-with=` oraz `--record=` są w formacie JSON*

Nagrywanie i odtwarzanie na żywo\
`python aiomacmarrum357.py --record='{"output_dir": "C:\\Users\\Mac\\radio357", "switch_file_times": ["9:00", "12:00"]}' --play`

Nagrywanie ze zmianą pliku o pełnej godzinie od momentu uruchomienia do północy,
a po każdej zmianie uruchomienie w tle polecenia `aac-to-m4a`\
`python aiomacmarrum357.py --record='{"output_dir": "C:\\Users\\Mac\\radio357", "switch_file_times": ["*:00", "0:00"], "on_file_end": "aac-to-m4a"}'`

Przykładowy skrypt `aac-to-m4a` – **aiomacmarrum357.py** przekaże ścieżkę do nagranego pliku jako pierwszy argument

```shell
#!/bin/bash
export AV_LOG_FORCE_NOCOLOR=1
exec /usr/bin/ffmpeg -loglevel warning -i "$1" -acodec copy "${1%.aac}.m4a"
```

Jeżeli w wierszu poleceń podane jest `--sleep=`, np. `--sleep=30`,
**aiomacmarrum357.py** czeka określoną ilość sekund przed uruchomieniem.

**Poniższe polecenia mają sens gdy **aiomacmarrum357.py** jest już uruchomiony.**

Odtwarzanie przy użyciu **mpv** strumienia na żywo z lokalnego serwera HTTP na hoście `localhost` aż do zakończenia nagrywania\
`mpv http://localhost:8357/live`

Odtwarzanie przy użyciu **mpv** z lokalnego serwera HTTP na hoście `192.168.0.1` od początku nagrywanego pliku, a potem na żywo aż do zakończenia nagrywania\
`mpv http://192.168.0.1:8357/file-then-live`

Jak powyżej, ale odtwarzanie jest kontynuowane po zakończeniu nagrywania\
`mpv http://localhost:8357/live?forever` \
`mpv http://192.168.0.1:8357/file-then-live?forever`

### Konfiguracja

Email oraz hasło do logowania na https://konto.radio357.pl muszą być podane w\
`%APPDATA%\macmarrum357\config.toml` – na Windows\
lub\
`~/.config/macmarrum357/config.toml` – na Unix.

W tym samym pliku można podać ścieżkę do odtwarzacza używanego przy `--play`, np. **mpv**, oraz opcje programu:\
`player_args = ['C:\Program Files\mpv\mpv.exe', '--force-window=immediate', '--fs=no']`\
jak również IP interfejsu sieciowego i port na którym strumień będzie udostępniany lokalnie\
`host = '0.0.0.0'`\
`port = 8357`\
Następująca instrukcja włączy icy-title w strumieniu /live, o ile odtwarzacz wspiera tę funkcję (**mpv** wspiera):\
`icy_title = true`

***Wskazówka**: `0.0.0.0` oznacza wszystkie interfejsy sieciowe, bez ograniczeń*

### Wymagania systemowe

- [Python](https://www.python.org/downloads/) >= 3.10
- [aiohttp](https://pypi.org/project/aiohttp/) – przetestowane na wersji 3.10.10
- [aiofiles](https://pypi.org/project/aiofiles/) – przetestowane na wersji 24.1.0
- [tomli-w](https://pypi.org/project/tomli-w/) – przetestowane na wersji 1.1.0

#### Opcjonalnie

- [tomli](https://pypi.org/project/tomli/) jeżeli Python jest w wersji 3.10 – przetestowane na wersji 1.0.0
- [aiodns](https://pypi.org/project/aiodns/) w przypadku konfiguracji `nameservers` – przetestowane na wersji 3.2.0
- [mpv](https://mpv.io/installation/) do odtwarzania – przetestowane na wersji 0.39.0

---

## macmarrum357 – alternatywny odtwarzacz Radia 357 dla patronów, działający z wiersza poleceń

Odtwarza Radio 357 na żywo, jako zalogowany użytkownik, z pominięciem komunikatu startowego.

Loguje użytkownika, pobiera ciasteczka i używa ich do odtwarzania strumienia przy pomocy **mpv**.

Jeżeli w wierszu poleceń podane jest `--sleep=`, np. `--sleep=30`,
**macmarrum357.py** czeka określoną ilość sekund przed uruchomieniem **mpv**.

Przekazuje wszystkie pozostałe argumenty wiersza polecenia do **mpv**,
żeby **macmarrum357** mógł być używany zamiennie z **mpv**.\
Np. polecenie `python macmarrum357.py --end=60:00 --mute=yes --stream-record=output.aac`\
zapisze bezgłośnie 60 minut strumienia do `output.aac`.

### Konfiguracja

Email oraz hasło do logowania na https://konto.radio357.pl muszą być podane w\
`%APPDATA%\macmarrum357\config.json` – na Windows\
lub\
`~/.config/macmarrum357/config.json` – na Unix.

W tym samym pliku można podać ścieżkę do **mpv** oraz opcje programu:\
`"mpv_command" : "C:\\Program Files\\mpv\\mpv.exe"`\
`"mpv_options": ["--force-window=immediate", "--cache-secs=1", "--fs=no"]`\
Gdy brak `mpv_command`, **macmarrum357** szuka **mpv** w `PATH`.

### Wymagania systemowe

- [Python](https://www.python.org/downloads/) >= 3.9
- [requests](https://pypi.org/project/requests/)
- [mpv](https://mpv.io/installation/)
