# 🔐 PyROXY: SOCKS5 Proxy with Custom Encryption

There is a client and a server with interfaces for working in code and for retransmitting system traffic through proxy
clients (like Proxifier).
This is a pre-configured version in commercial branch from the master branch that can be deployed.
To deploy this project to the server, you need to follow a few small, simple steps:

---

## 📦 Installation
```bash
git clone https://github.com/Pos1t1veGuy/PyROXY.git
```
After that you need to install python3 (3.13 is required):
```bash
apt install python3
```
By default proxy have not requirements, but modules have. `requirements.txt` is in a modules folders (ciphers, wrappers),
you may install it by:
```bash
pip install -r ./module_name/requirements.txt
```
Or simply:
```bash
python install_packages.py
```
To install every requirement of all modules.

---

## 🚀 Start
[main.py](main.py)/[main_nomux.py](main_nomux.py) setup a server and provide a simple interface to launch the server. (`main.py --help` to details)
Make host=0.0.0.0 to make access from outside, by default host=127.0.0.1, port=8080, logging=info.
```bash
python3 main.py --host 0.0.0.0 --port 80 --logging info
```
Better to connect nginx, launch it on 0.0.0.0:80 and set the proxy address to 127.0.0.1:8080 (by default).

If you want to use a telegram bot, setup the [config.json](telegram_bot/config.json) in `telegram_bot` folder.
Template:
```json
{
  "API_TOKEN": "...",
  "author_link": "...",
  "author_id": ...,
  "bot_url": "...",
  "ciphers": {
    "default": "Default cipher description.",
    "ChaCha20-Poly1305": "ChaCha20 cipher description.",
    "AES_CTR": "AES CTR cipher description."
  },
  "servers": {
    "proxy_server_host": "server_view_name"
  },
  "clients_url": "...",
  "payment_methods": {
    "default": {
      "name": "Card payment (payment will occur within a few hours)",
      "token": "Your pay card",
      "invoice": false,
      "commission": {
        "percent": 0,
        "fixed": 0
      }
    }
  },
  "pricing": {
    "free_3_days": {
      "price": 0,
      "comment": "3 дня",
      "duration_days": 3,
      "once": true
    },
    "one_day": {
      "price": 10,
      "comment": "1 день",
      "duration_days": 1,
      "once": false
    },
  },
  "money_to_pay": [10, 100, 150, 300, 500, 1000, 5000, 10000, 20000]
}
```
Then launch [main.py](telegram_bot/main.py) in `telegram_bot` folder.

---

## 🧩 Compile a client
To compile python script you need to install PyInstaller:
```bash
pip install pyinstaller
```
1. Then you need to compile clients in [user_interface](user_interface) folder. Select a system from the available ones there.
2. Launch `compile.sh`/`compile.bat` depending on your system (bat for Windows, sh for Unix)
3. `/dist` folder should to appear there, in this folder is client compiled files, **that user can to launch.**

---

## 🧩 Make your ciphering

The core of this proxy is the `Cipher` class, which defines all stages of the SOCKS5 handshake and the methods for traffic encryption/decryption.

You can override **handshake stages** to change how the proxy negotiates methods, authenticates, or sends commands,
or use created base [ciphers](ciphers).

File [default_server_key](telegram_bot/default_server_key) **contain default server key,
that user need to use TO MAKE HANDSHAKE**, after that user can use any other keys.

---

## 🤝 How to connect

To establish a proxy connection at user machine:
* Launch `client` with your CLI arguments, `client --help` to details.
* Make `profile.pyroxy` file in the same with `client` folder, put arguments there and launch STARTER (it reads `profile.pyroxy` arguments setup)

`profile.pyroxy` file must be view like:
```
host=...
username=...
password=...
key=...
cipher=...
default_key=...
```

Put the server hosting IP in host=,
Put `default_server_key` default_key=,
cipher must be one of the available on the server (`chacha20`/`aes_ctr`/`none`/`default` by default provided),
username and password must be registered in base using database handler from [db_handlers.py](base_db_handlers.py)
(telegram bot do it automaticaly)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.