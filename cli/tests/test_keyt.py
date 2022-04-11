#!/usr/bin/env python3
"""Tests for `keyt` package."""

from keyt import gen_password


def test_gen_password():
    password = gen_password(d="example.com", u="admin", m="admin")
    assert password == "Fg0XjW@a=vWi@3qGBjo|Vlic7Wo9`zVKp!{Vl_Bp"


def test_gen_password_max():
    password = gen_password(d="example.com", u="admin", m="admin", f="max")
    assert isinstance(password, str)
    assert len(password) == 40
    assert password == "Fg0XjW@a=vWi@3qGBjo|Vlic7Wo9`zVKp!{Vl_Bp"


def test_gen_password_high():
    password = gen_password(d="example.com", u="admin", m="admin", f="high")
    assert isinstance(password, str)
    assert len(password) == 16
    assert password == "Fg0XjW@a=vWi@3qG"


def test_gen_password_mid():
    password = gen_password(d="example.com", u="admin", m="admin", f="mid")
    assert isinstance(password, str)
    assert len(password) == 16
    assert password == "5w8Hv23ZUvJCRt2t"


def test_gen_password_pin():
    password = gen_password(d="example.com", u="admin", m="admin", f="pin")
    assert isinstance(password, int)
    assert len(str(password)) == 4
    assert password == 3070


def test_gen_password_pin6():
    password = gen_password(d="example.com", u="admin", m="admin", f="pin6")
    assert isinstance(password, int)
    assert len(str(password)) == 6
    assert password == 307084
