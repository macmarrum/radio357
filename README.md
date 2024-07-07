# radio357

## macmarrum357 – alternatywny odtwarzacz patrona Radia357, działający z wiersza poleceń

Odtwarza Radio 357 na żywo, jako zalogowany użytkownik, z pominięciem komunikatu startowego.

Loguje użytkownika, pobiera ciasteczka i używa ich do odtwarzania strumienia przez **mpv**.

Przekazuje wszystkie argumenty wiersza polecenia do **mpv**, 
żeby **macmarrum357** mógł być używany zamiennie z **mpv**.\
Np. dodanie po `python macmarrum357.py`\
` --end=60:00 --mute=yes --stream-record=output.aac`\
zapisze bezgłośnie 60 minut strumienia do `output.aac`.

### Konfiguracja

Email oraz hasło do logowania na https://konto.radio357.pl muszą być podane w\
`%APPDATA%/macmarrum357.json` – na Windows\
lub\
`~/.config/macmarrum357.json` – na Unix.

W tym samym pliku można podać ścieżkę do **mpv** oraz opcje programu:\
`"mpv_command" : "C:\\Program Files\\mpv\\mpv.exe"`\
`"mpv_options": ["--force-window=immediate"]`\
Gdy brak `mpv_command`, **macmarrum357** szuka **mpv** w `PATH`.

### Wymagania systemowe

- [Python](https://www.python.org/downloads/) >= 3.9
- [requests](https://pypi.org/project/requests/)
- [mpv](https://mpv.io/installation/)
