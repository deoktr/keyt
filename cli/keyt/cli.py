#!/usr/bin/env python3
"""Keyt CLI, a stateless password manager and generator."""
import argparse
import time
from base64 import b85encode
from enum import Enum, auto
from getpass import getpass
from hashlib import blake2b, scrypt
from typing import Union

try:
    from base58 import b58encode

    BASE58_INSTALLED = True
except ImportError:
    BASE58_INSTALLED = False

try:
    import pyperclip

    PYPERCLIP_INSTALLED = True
except ImportError:
    PYPERCLIP_INSTALLED = False


__version__ = "0.4.0"


class F(Enum):
    """Formats available."""

    max = auto()
    high = auto()
    mid = auto()
    pin = auto()
    pin6 = auto()


def gen_password(d, u, m, c=0, f=F.max):
    """Keyt password generation algorithm."""
    salt = u.encode()
    key = scrypt(m.encode(), salt=salt, n=16384, r=8, p=2)

    c = str(c) if c > 0 else ""
    data = (d.lower() + c + u).encode()
    seed = blake2b(data, key=key).hexdigest().encode()

    if f == F.max:
        return b85encode(seed).decode()[:40]
    elif f == F.high:
        return b85encode(seed).decode()[:16]
    elif f == F.mid:
        if BASE58_INSTALLED:
            return b58encode(seed).decode()[:16]
        else:
            raise Exception("Install `base58` or use another format.")
    elif f == F.pin:
        return int(str(int(seed, 16))[:4])
    elif f == F.pin6:
        return int(str(int(seed, 16))[:6])
    else:
        raise Exception(f"invalid format '{f}'.")


def main():
    """CLI arguments parser init."""
    parser = argparse.ArgumentParser(
        prog="keyt",
        usage="keyt [domain] [username] [master_password] [options]",
        description="%(prog)s stateless password manager and generator.",
    )
    parser.add_argument("-V", "--version", action="store_true")
    parser.add_argument(
        "domain",
        help="Domain name/IP/service.",
        nargs="?",
    )
    parser.add_argument(
        "username",
        help="Username/Email/ID.",
        nargs="?",
    )
    parser.add_argument(
        "master_password",
        help="Master password used during the password generation.",
        nargs="?",
    )
    parser.add_argument(
        "-c",
        "--counter",
        help="An integer that can be incremented to change our the password. "
        "default=0.",
        type=int,
        default=0,
    )
    parser.add_argument(
        "-f",
        "--format",
        help="Password format can be: 'max', 'high', 'mid', 'pin' or 'pin6'. "
        "default=max.",
        default="max",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output the password, by default copy it to the clipboard.",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--timer",
        help="Time before flushing the clipboard. default=20s.",
        type=int,
        nargs="?",
        default=20,
    )
    return dispatch(parser)


def dispatch(parser):
    """Dispatch from the CLI parser."""
    args = parser.parse_args()

    if args.version:
        print(f"keyt version {__version__}")
        return 0

    d = args.domain
    if d is None:
        try:
            d = str(input("domain: "))
        except KeyboardInterrupt:
            return 1

    u = args.username
    if u is None:
        try:
            u = str(input("username: "))
        except KeyboardInterrupt:
            return 1

    m = args.master_password
    if m is None:
        try:
            m = getpass("master password: ")
        except KeyboardInterrupt:
            return 1

    f = F[args.format]

    try:
        password = gen_password(d=d, u=u, m=m, c=args.counter, f=f)
    except Exception as e:
        print(e)
        return 1

    if args.output:
        print(password)
        return 0

    if not PYPERCLIP_INSTALLED:
        print("`pyperclip` is needed.\nYou can also use the `-o` flag.")
        return 1

    pyperclip.copy(password)
    timer = args.timer
    if timer and timer > 0:
        print(f"Password copied to the clipboard for {timer}s.")
        try:
            time.sleep(timer)
        except KeyboardInterrupt:
            pass
        pyperclip.copy("")  # remove the content of the clipboard
        return 0
    else:
        print("Password copied to the clipboard.")
        return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
