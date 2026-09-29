import pytest

from prism.detector import detect_ioc
from prism.models import IOCType


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", IOCType.IPV4),
        ("example.com", IOCType.DOMAIN),
        ("https://example.com/login", IOCType.URL),
        ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
        ("a" * 40, IOCType.SHA1),
        ("a" * 64, IOCType.SHA256),
    ],
)
def test_detect(value, expected):
    assert detect_ioc(value).type == expected


def test_empty():
    with pytest.raises(ValueError):
        detect_ioc("")


def test_ipv6_not_supported():
    with pytest.raises(ValueError, match="IPv6"):
        detect_ioc("2001:4860:4860::8888")
