import ipaddress
import re
from urllib.parse import urlparse

from app.models import IndicatorType

_HASHES = {
    32: IndicatorType.MD5,
    40: IndicatorType.SHA1,
    64: IndicatorType.SHA256,
}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def detect_type(indicator: str) -> IndicatorType:
    """Detect IOC type; raise ValueError if unrecognised."""
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
    if ioc_type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}:
        return indicator.lower()
    if ioc_type is IndicatorType.DOMAIN:
        return indicator.lower().rstrip(".")
    if ioc_type is IndicatorType.IPV6:
        return str(ipaddress.ip_address(indicator))
    return indicator
