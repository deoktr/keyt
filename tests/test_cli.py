from keyt.cli import parse_args


def test_parse_args():
    parser = parse_args(["example.com", "admin", "password"])
    assert parser.domain == "example.com"
    assert parser.username == "admin"
    assert parser.master_password == "password"
    assert parser.counter == 0
    assert parser.format == "max"
    assert isinstance(parser.output, bool)
    assert isinstance(parser.timer, int)


def test_parse_args_format():
    parser = parse_args(["example.com", "admin", "password", "-f=high"])
    assert parser.format == "high"


def test_parse_args_counter():
    parser = parse_args(["example.com", "admin", "password", "-c=42"])
    assert parser.counter == 42


def test_parse_args_output():
    parser = parse_args(["example.com", "admin", "password", "-o"])
    assert parser.output is True


def test_parse_args_timer():
    parser = parse_args(["example.com", "admin", "password", "-t=42"])
    assert parser.timer == 42


def test_parse_args_version():
    parser = parse_args(["--version"])
    assert parser.version is True
