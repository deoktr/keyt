#!/usr/bin/env python3
import argparse
import base64
import hashlib
import time
from getpass import getpass

try:
    from keyt import __version__
except ImportError:
    __version__ = "0.2"


PASS_LEN = 40
SHORT_PASS_LEN = 15
B64_ALTCHARS = b"42"

# CLI specific options
TIMER = 20
ESCAPE_DEFAULT = False


def gen_password(
    domain: str,
    username: str,
    master_password: str,
    domain_counter: int = 0,
    l: int = PASS_LEN,
):
    str_domain_counter = "" if not domain_counter else str(domain_counter)
    data = domain.lower() + str_domain_counter + username + master_password

    data_hash = hashlib.sha256(data.encode()).hexdigest()
    b85_pass = base64.b85encode(data_hash.encode()).decode()
    return b85_pass[:l]


def convert_short_simple(p: str, l: int = SHORT_PASS_LEN):
    """Convert to the short and simple version."""
    return base64.b64encode(p.encode(), altchars=B64_ALTCHARS).decode()[:l]


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
        "--domain-counter",
        help="An integer representing the number of times you changed your "
        "password, increment to change password.",
        action="store",
        type=int,
    )
    parser.add_argument(
        "-s",
        "--short-simple",
        help="Short and simple password, generate a 15 char password variant "
        "instead of the 40 default, and without special characters.",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output the password, by default the password is added to the "
        "clipboard.",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--timer",
        help=f"Time before flushing the clipboard, default={TIMER}s, use 0 "
        "to disable the timer.",
        action="store",
        type=int,
        nargs="?",
        default=TIMER,
    )

    return dispatch(parser)


def dispatch(parser):
    args = parser.parse_args()

    if args.version:
        print("keyt version {}".format(__version__))
        return 0

    domain = args.domain
    if domain is None:
        try:
            domain = str(input("domain: "))
        except KeyboardInterrupt:
            return 1

    username = args.username
    if username is None:
        try:
            username = str(input("username: "))
        except KeyboardInterrupt:
            return 1

    master_password = args.master_password
    if master_password is None:
        try:
            master_password = getpass("master password: ")
        except KeyboardInterrupt:
            return 1

    password = gen_password(
        domain=domain,
        username=username,
        master_password=master_password,
        domain_counter=args.domain_counter,
    )

    if args.short_simple:
        password = convert_short_simple(password)

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
        print("Password copied to the clipboard for {}s.".format(timer))
        try:
            time.sleep(timer)
        except KeyboardInterrupt:
            pass
        pyperclip.copy("")  # remove the content of the clipboard
    else:
        print("Password copied to the clipboard.")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
