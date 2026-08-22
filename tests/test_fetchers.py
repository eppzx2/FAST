"""
Test Fetchers Module

core.fetchers modulunun testləri.

Qeyd: Bu mühitdə (sandbox) abuse.ch və spamhaus.org domenlərinə
şəbəkə çıxışı bloklu ola bilər (egress allowlist). Ona görə real
HTTP sorğuları ilə yanaşı, unittest.mock ilə network-dən asılı
olmayan testlər də yazılıb.
"""

import pytest
from unittest.mock import patch, MagicMock
import requests
from core import fetchers


# ---------------------------------------------------------
# LIVE TESTS (real şəbəkə çıxışı lazımdır, xəta-toleranslığı yoxlayır)
# ---------------------------------------------------------

def test_fetch_feodo():
    """
    Feodo Tracker fetch funksiyasının testi.
    
    Mümkün hallar:
    - Feed əlçatan olarsa: IOC siyahısı qaytarır (empty list də ola bilər)
    - Feed əlçatan deyilsə: [] qaytarır
    - JSON parse xətası: [] qaytarır
    """
    result = fetchers.fetch_feodo()
    
    # Həmişə list olmalı (xəta halında belə crash olmamalı)
    assert isinstance(result, list), "fetch_feodo() list qaytarmalı"
    
    for item in result:
        assert isinstance(item, dict), "Hər IOC dict olmalı"
        if "ip_address" in item:
            assert isinstance(item["ip_address"], str), "ip_address string olmalı"


def test_fetch_urlhaus():
    """
    URLhaus fetch funksiyasının testi.
    
    Xəta halında belə [] qaytarmalı, crash olmamalıdır.
    """
    result = fetchers.fetch_urlhaus()
    assert isinstance(result, list), "fetch_urlhaus() list qaytarmalı"
    for item in result:
        assert isinstance(item, dict), "Hər IOC dict olmalı"


def test_fetch_malwarebazaar():
    """
    MalwareBazaar fetch funksiyasının testi.
    
    Xəta halında belə [] qaytarmalı, crash olmamalıdır.
    """
    result = fetchers.fetch_malwarebazaar()
    assert isinstance(result, list), "fetch_malwarebazaar() list qaytarmalı"
    for item in result:
        assert isinstance(item, dict), "Hər IOC dict olmalı"


def test_fetch_spamhaus():
    """
    Spamhaus fetch funksiyasının testi.
    
    Xəta halında belə [] qaytarmalı, crash olmamalıdır.
    """
    result = fetchers.fetch_spamhaus()
    assert isinstance(result, list), "fetch_spamhaus() list qaytarmalı"
    for item in result:
        assert isinstance(item, dict), "Hər IOC dict olmalı"
        assert "cidr" in item, "Spamhaus IOC-larda 'cidr' sahəsi olmalı"


def test_fetch_all_feeds():
    """
    fetch_all_feeds() funksiyasının testi - bütün 4 feed-i çağırır.
    """
    result = fetchers.fetch_all_feeds()
    
    assert isinstance(result, dict), "fetch_all_feeds() dict qaytarmalı"
    assert set(result.keys()) == {"feodo", "urlhaus", "malwarebazaar", "spamhaus"}
    
    for feed_name, iocs in result.items():
        assert isinstance(iocs, list), f"{feed_name} nəticəsi list olmalı"


# ---------------------------------------------------------
# MOCK TESTS (network-dən asılı olmadan - CI/CD üçün etibarlı)
# ---------------------------------------------------------

def test_fetch_feodo_success_mocked():
    """
    Feodo fetcher-in uğurlu HTTP cavabı ilə düzgün parse etdiyini yoxlayır.
    """
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": [
            {"ip_address": "1.2.3.4", "botnet": "dridex", "last_dns_query": "2024-01-15"}
        ]
    }
    mock_response.raise_for_status = MagicMock()
    
    with patch("requests.get", return_value=mock_response):
        result = fetchers.fetch_feodo()
    
    assert len(result) == 1
    assert result[0]["ip_address"] == "1.2.3.4"


def test_fetch_feodo_network_error_mocked():
    """
    Feodo fetcher-in şəbəkə xətasında crash olmadan [] qaytardığını yoxlayır.
    """
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError()):
        result = fetchers.fetch_feodo()
    
    assert result == [], "Şəbəkə xətasında boş siyahı qaytarılmalı"


def test_fetch_feodo_timeout_mocked():
    """
    Feodo fetcher-in timeout zamanı crash olmadan [] qaytardığını yoxlayır.
    """
    with patch("requests.get", side_effect=requests.exceptions.Timeout()):
        result = fetchers.fetch_feodo()
    
    assert result == [], "Timeout zamanı boş siyahı qaytarılmalı"


def test_fetch_urlhaus_success_mocked():
    """
    URLhaus fetcher-in uğurlu CSV cavabını düzgün parse etdiyini yoxlayır.
    """
    mock_response = MagicMock()
    mock_response.text = (
        "# Comment line\n"
        '# id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n'
        '"1","2024-01-15 10:00:00","http://evil.com/m.exe","online","malware_download","exe","link","abuse_ch"\n'
    )
    mock_response.raise_for_status = MagicMock()
    
    with patch("requests.get", return_value=mock_response):
        result = fetchers.fetch_urlhaus()
    
    assert len(result) == 1
    assert result[0]["url"] == "http://evil.com/m.exe"


def test_fetch_urlhaus_http_error_mocked():
    """
    URLhaus fetcher-in HTTP xətasında (403, 500 və s.) crash olmadan [] qaytardığını yoxlayır.
    """
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=MagicMock(status_code=403))
    
    with patch("requests.get", return_value=mock_response):
        result = fetchers.fetch_urlhaus()
    
    assert result == []


def test_fetch_malwarebazaar_success_mocked():
    """
    MalwareBazaar fetcher-in uğurlu CSV cavabını düzgün parse etdiyini yoxlayır.
    """
    mock_response = MagicMock()
    mock_response.text = (
        "# Comment\n"
        '# "first_seen_utc","sha256_hash","md5_hash","file_name","file_type_guess","signature"\n'
        '"2024-01-15 10:00:00","abc123","def456","malware.exe","exe","TrojanX"\n'
    )
    mock_response.raise_for_status = MagicMock()
    
    with patch("requests.get", return_value=mock_response):
        result = fetchers.fetch_malwarebazaar()
    
    assert len(result) == 1
    assert result[0]["sha256_hash"] == "abc123"


def test_fetch_spamhaus_success_mocked():
    """
    Spamhaus fetcher-in uğurlu text cavabını düzgün parse etdiyini yoxlayır.
    """
    mock_response = MagicMock()
    mock_response.text = (
        "; Spamhaus DROP List\n"
        "; Last updated 2024-01-15\n"
        '192.168.1.0/24 ; SBL12345\n'
        '10.0.0.0/8 ; "Spam Source"\n'
    )
    mock_response.raise_for_status = MagicMock()
    
    with patch("requests.get", return_value=mock_response):
        result = fetchers.fetch_spamhaus()
    
    assert len(result) == 2
    assert result[0]["cidr"] == "192.168.1.0/24"
    assert result[0]["reason"] == "SBL12345"
    assert result[1]["cidr"] == "10.0.0.0/8"


def test_fetch_all_feeds_partial_failure_mocked():
    """
    fetch_all_feeds() -un bəzi feed-lər uğursuz olsa belə,
    digərləri ilə davam etdiyini (crash olmadan) yoxlayır.
    """
    def side_effect(url, **kwargs):
        if "feodo" in url:
            raise requests.exceptions.ConnectionError("Simulated failure")
        mock_response = MagicMock()
        mock_response.text = "; comment\n192.168.1.0/24 ; test\n"
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status = MagicMock()
        return mock_response
    
    with patch("requests.get", side_effect=side_effect):
        result = fetchers.fetch_all_feeds()
    
    # Feodo uğursuz oldu amma nəticə hələ də dict-dir, crash yoxdur
    assert isinstance(result, dict)
    assert result["feodo"] == []
    assert set(result.keys()) == {"feodo", "urlhaus", "malwarebazaar", "spamhaus"}
