import ipaddress
import re
from urllib.parse import urlparse

from app.models import HASH_TYPES, IndicatorType

_HASHES = {
    32: IndicatorType.MD5,
    40: IndicatorType.SHA1,
    64: IndicatorType.SHA256,
}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
# Defanged notation used in reports/tickets: hxxp://evil[.]com, 1.2.3[.]4, user[at]x(dot)com
_REFANG = (
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"^fxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
)


def refang(indicator: str) -> str:
    """Undo common defanging so analysts can paste IOCs straight from reports."""
    value = indicator.strip()
    for pattern, repl in _REFANG:
        value = pattern.sub(repl, value)
    return value


def detect_type(indicator: str) -> IndicatorType:
    """Detect IOC type; raise ValueError if unrecognised."""
    indicator = refang(indicator)
    try:
        ip = ipaddress.ip_address(indicator)
        return IndicatorType.IPV4 if ip.version == 4 else IndicatorType.IPV6
    except ValueError:
        pass
    if _HEX.match(indicator) and len(indicator) in _HASHES:
        return _HASHES[len(indicator)]
    if "://" in indicator:
        parsed = urlparse(indicator)
        if parsed.scheme in {"http", "https", "ftp"} and parsed.hostname:
            return IndicatorType.URL
        raise ValueError("invalid URL")
    if _DOMAIN.match(indicator):
        return IndicatorType.DOMAIN
    raise ValueError("unrecognised indicator type")


def normalize(indicator: str, ioc_type: IndicatorType) -> str:
    indicator = refang(indicator)
    if ioc_type in HASH_TYPES:
        return indicator.lower()
    if ioc_type is IndicatorType.DOMAIN:
        return indicator.lower().rstrip(".")
    if ioc_type is IndicatorType.IPV6:
        return str(ipaddress.ip_address(indicator))
    if ioc_type is IndicatorType.URL:
        parsed = urlparse(indicator)
        # scheme and host are case-insensitive; path is not
        return parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()).geturl()
    return indicator
