import pytest

from app.models import IndicatorType as T
from app.services.detector import detect_type, normalize, refang


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1.2.3.4", T.IPV4),
        ("2001:db8::1", T.IPV6),
        ("example.com", T.DOMAIN),
        ("sub.example.co.uk", T.DOMAIN),
        ("a" * 32, T.MD5),
        ("b" * 40, T.SHA1),
        ("C" * 64, T.SHA256),
        ("https://example.com/path?q=1", T.URL),
        ("http://1.2.3.4/x", T.URL),
    ],
)
def test_detect(value, expected):
    assert detect_type(value) is expected


@pytest.mark.parametrize("value", ["not an ioc", "999.1.1.1x", "javascript://x", "zz" * 16, "foo"])
def test_detect_invalid(value):
    with pytest.raises(ValueError):
        detect_type(value)


def test_normalize():
    assert normalize("ABCDEF" + "0" * 26, T.MD5) == "abcdef" + "0" * 26
    assert normalize("Example.COM.", T.DOMAIN) == "example.com"
    assert normalize("2001:DB8:0::BAD", T.IPV6) == "2001:db8::bad"
    assert normalize("HTTP://Evil.Example/Path", T.URL) == "http://evil.example/Path"


@pytest.mark.parametrize(
    ("defanged", "expected", "type_"),
    [
        ("hxxp://evil[.]example/login", "http://evil.example/login", T.URL),
        ("hXXps://evil(.)example", "https://evil.example", T.URL),
        ("185.220.101[.]1", "185.220.101.1", T.IPV4),
        ("evil[dot]example", "evil.example", T.DOMAIN),
        ("evil{.}example", "evil.example", T.DOMAIN),
    ],
)
def test_refang(defanged, expected, type_):
    assert refang(defanged) == expected
    assert detect_type(defanged) is type_
    assert normalize(defanged, type_) == expected
