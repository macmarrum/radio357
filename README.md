# radio357

## macmarrum357 – alternatywny odtwarzacz patrona Radia357, działający z wiersza poleceń

Odtwarza Radio 357 na żywo, jako zalogowany użytkownik, z pominięciem komunikatu startowego.

Loguje użytkownika, pobiera ciasteczka i używa ich do odtwarzania strumienia przy pomocy **mpv**.

Opcjonalnie czeka określoną ilość sekund przed włączeniem **mpv**,
jeżeli `--sleep SECONDS` jest podane w wierszu poleceń.

Przekazuje wszystkie argumenty wiersza polecenia do **mpv**, 
żeby **macmarrum357** mógł być używany zamiennie z **mpv**.\
Np. dodanie po `python macmarrum357.py`\
` --end=60:00 --mute=yes --stream-record=output.aac`\
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

---

## aiomacmarrum357 – alternatywny odtwarzacz/nagrywarka patrona Radia 357, działający z wiersza poleceń

Odtwarza i/lub nagrywa Radio 357 na żywo, jako zalogowany użytkownik, z pominięciem komunikatu startowego.

Loguje użytkownika, pobiera ciasteczka i używa ich do odbierania strumienia na żywo.
Pobierany strumień udostępnia lokalnie przez http dla potrzeb odtwarzania przy pomocy kompatybilnego programu, np. **mpv**.
Opcjonalnie nagrywa strumień do jednego lub kilku plików, zmieniając je o określonych porach.

Odtwarzanie\
`python aiomacmarrum357.py --play`\
lub\
`python aiomacmarrum357.py --play-with='["C:\\Program Files\\mpv\\mpv.exe", "--force-window=immediate", "--cache-secs=1", "--fs=no"]'`

Nagrywanie\
`python aiomacmarrum357.py --record='{"output_dir": "/tmp/r357", "switch_file_times": ["9:00", "12:00"]}'`

Zapisuje program na żywo do plików, zmieniając je o określonych porach,
np. w przypadku uruchomienia o 6:00 zapisze dwa pliki:
* 2024-09-23,Mon_06.aac - obejmujący audycję do 9:00
* 2024-09-23,Mon_09.aac - obejmujący audycję do 12:00

Zmiana pliku co godzinę od teraz do północy\
`--record={"switch_file_times": ["*:00", "0:00"]}`

*Wskazówka: wartości dla opcji --play-with= oraz --record= są w formacie JSON*

Opcjonalnie czeka określoną ilość sekund przed uruchomieniem odtwarzania (`--play` lub `--play-with=`),
jeżeli `--sleep=` jest podane w wierszu poleceń, np. `--sleep=30`.

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

- [Python](https://www.python.org/downloads/) >= 3.10
- [aiohttp](https://pypi.org/project/aiohttp/)
- [aiofiles](https://pypi.org/project/aiofiles/)
- [mpv](https://mpv.io/installation/)

Opcjonalnie
- [aiodns](https://pypi.org/project/aiodns/)
