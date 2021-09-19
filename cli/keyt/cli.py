#!/usr/bin/env python3
import argparse
import time
from base64 import b85encode
from getpass import getpass
from hashlib import blake2b, scrypt

__version__ = "0.3.0"

SCRYPT_N = 16384  # 2^14
SCRYPT_R = 8
SCRYPT_P = 2
TIMER = 20


def gen_password(d, u, m, c=0, f="max"):
    salt = u.encode()
    key = scrypt(m.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)

    c = str(c) if c > 0 else ""
    data = (d.lower() + c + u).encode()
    seed = blake2b(data, key=key).hexdigest().encode()

    if f == "max":
        return b85encode(seed).decode()[:40]
    elif f == "high":
        return b85encode(seed).decode()[:16]
    elif f == "mid":
        try:
            from base58 import b58encode
        except ImportError:
            raise Exception("Install `base58` or use another format.")
        return b58encode(seed).decode()[:16]
    elif f == "pin":
        return str(int(seed, 16))[:4]
    elif f == "pin6":
        return str(int(seed, 16))[:6]
    else:
        raise Exception(f"invalid format '{f}'.")


def main():
    parser = argparse.ArgumentParser(
        prog="keyt",
        usage="keyt [domain] [username] [master_password] [options]",
        description="%(prog)s stateless password manager and generator.",
    )
    parser.add_argument("--version", action="store_true")
    parser.add_argument(
        "domain",
        help="Domain name/IP/service.",
        type=str,
        nargs="?",
    )
    parser.add_argument(
        "username",
        help="Username/Email/ID.",
        type=str,
        nargs="?",
    )
    parser.add_argument(
        "master_password",
        help="Master password used during the password generation.",
        type=str,
        nargs="?",
    )
    parser.add_argument(
        "-c",
        "--counter",
        help="An integer that can be incremented to change our the password. "
        "default=0.",
        action="store",
        type=int,
        default=0,
    )
    parser.add_argument(
        "-f",
        "--format",
        help="Password format can be: 'max', 'high', 'mid', 'pin' or 'pin6'. "
        "default=max.",
        action="store",
        default="max",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output the password, by default the password is copied to the "
        "clipboard.",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--timer",
        help=f"Time before flushing the clipboard. default={TIMER}s, use 0 "
        "or nothing to disable the timer.",
        action="store",
        type=int,
        nargs="?",
        default=TIMER,
    )
    return dispatch(parser)


def dispatch(parser):
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

    try:
        password = gen_password(d=d, u=u, m=m, c=args.counter, f=args.format)
    except Exception as e:
        print(e)
        return 1

    if args.output:
        print(password)
        return 0

    try:
        import pyperclip
    except ImportError:
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
