# keyt

[![keyt-pypi](https://img.shields.io/pypi/v/keyt.svg)](https://pypi.python.org/pypi/keyt)

keyt is a stateless password manager and generator.

**Derive don't store.**

The intent of this program is to have a password manager and generator without storing any data anywhere in any form. The password is derived from a master password.

⚠️ Every passwords are derived from your master password, if you loose it you will lose access to all your account, be carreful.

## Install CLI

```shell
pip install keyt
```

## Usage

```txt
usage: keyt [domain] [username] [master_password] [options]

keyt stateless password manager and generator.

positional arguments:
  domain                Domain name/IP/service.
  username              Username/Email/ID.
  master_password       Master password used during the password generation.

optional arguments:
  -h, --help            show this help message and exit
  --version
  -c COUNTER, --counter COUNTER
                        An integer that can be incremented to change our the
                        password. default=0.
  -f FORMAT, --format FORMAT
                        Password format can be: 'max', 'high', 'mid', 'pin' or
                        'pin6'. default=max.
  -o, --output          Output the password, by default copy it to the
                        clipboard.
  -t [TIMER], --timer [TIMER]
                        Time before flushing the clipboard. default=20s.
```

## Examples

```text
$ keyt
domain: example.com
username: admin
master password:
Password copied to the clipboard for 20s.

$ keyt example.com admin admin
Password copied to the clipboard for 20s.

$ keyt example.com admin admin -o
Fg0XjW@a=vWi@3qGBjo|Vlic7Wo9`zVKp!{Vl_Bp

$ keyt example.com admin admin -o -f mid
5w8Hv23ZUvJCRt2t

$ keyt example.com admin admin -o -f pin
3070
```

```python
>>> from keyt import gen_password
>>> gen_password(d="example.com", u="admin", m="admin")
'Fg0XjW@a=vWi@3qGBjo|Vlic7Wo9`zVKp!{Vl_Bp'
```

## Troubleshooting

If you get an error on pyperclip it's probably because you need to install additionnal packages.

For example on Ubuntu:

```bash
sudo apt-get install xclip
```

More infos on pyperclip description: [pypi pyperclip](https://pypi.org/project/pyperclip/).

## License

keyt is licensed under MIT.
