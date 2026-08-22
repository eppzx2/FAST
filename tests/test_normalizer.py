"""
Test Normalizer Module

core.normalizer modulunun testləri.
"""

import pytest
from core import normalizer


def test_normalize_feodo():
    """
    Feodo məlumatlarının normallaşdırılması testi.
    
    Standart sxemə düzgün map olunduğunu, tags-in botnet adını 
    ehtiva etdiyini yoxlayır.
    """
    raw = [
        {"ip_address": "1.2.3.4", "botnet": "dridex", "last_dns_query": "2024-01-15"},
        {"ip_address": "5.6.7.8", "botnet": "emotet", "last_dns_query": "2024-01-16"},
    ]
    
    result = normalizer.normalize_feodo(raw)
    
    assert len(result) == 2
    assert result[0]["ioc_value"] == "1.2.3.4"
    assert result[0]["ioc_type"] == "ip"
    assert result[0]["source_feed"] == "feodo"
    assert "dridex" in result[0]["tags"]
    assert result[0]["first_seen"] == result[0]["last_seen"]


def test_normalize_feodo_missing_ip_skipped():
    """
    ip_address sahəsi olmayan qeydlərin skip edildiyini (crash olmadan) yoxlayır.
    """
    raw = [
        {"botnet": "dridex", "last_dns_query": "2024-01-15"},  # ip_address yoxdur
        {"ip_address": "5.6.7.8", "botnet": "emotet", "last_dns_query": "2024-01-16"},
    ]
    
    result = normalizer.normalize_feodo(raw)
    
    assert len(result) == 1
    assert result[0]["ioc_value"] == "5.6.7.8"


def test_normalize_urlhaus():
    """
    URLhaus məlumatlarının normallaşdırılması testi.
    
    URL-in 'url' tipi olaraq map olunduğunu, threat və tags-in 
    birləşdirildiyini yoxlayır.
    """
    raw = [
        {
            "url": "http://evil.com/malware.exe",
            "dateadded": "2024-01-15 10:30:00",
            "threat": "malware_download",
            "tags": "exe,trojan",
        },
    ]
    
    result = normalizer.normalize_urlhaus(raw)
    
    assert len(result) == 1
    assert result[0]["ioc_value"] == "http://evil.com/malware.exe"
    assert result[0]["ioc_type"] == "url"
    assert result[0]["source_feed"] == "urlhaus"
    assert "malware_download" in result[0]["tags"]
    assert "exe" in result[0]["tags"]
    assert "trojan" in result[0]["tags"]


def test_normalize_malwarebazaar():
    """
    MalwareBazaar məlumatlarının normallaşdırılması testi.
    
    SHA256-nın üstünlük təşkil etdiyini, hash tipin düzgün olduğunu yoxlayır.
    """
    raw = [
        {
            "sha256_hash": "abc123def456",
            "md5_hash": "aaa111",
            "first_seen_utc": "2024-01-15 10:30:00",
            "file_name": "malware.exe",
            "signature": "TrojanX",
        },
    ]
    
    result = normalizer.normalize_malwarebazaar(raw)
    
    assert len(result) == 1
    assert result[0]["ioc_value"] == "abc123def456"  # sha256 üstünlük təşkil edir
    assert result[0]["ioc_type"] == "hash"
    assert result[0]["source_feed"] == "malwarebazaar"
    assert "TrojanX" in result[0]["tags"]


def test_normalize_malwarebazaar_fallback_to_md5():
    """
    sha256_hash olmadıqda md5_hash-in istifadə edildiyini yoxlayır.
    """
    raw = [
        {"md5_hash": "aaa111", "first_seen_utc": "2024-01-15 10:30:00"},
    ]
    
    result = normalizer.normalize_malwarebazaar(raw)
    
    assert len(result) == 1
    assert result[0]["ioc_value"] == "aaa111"


def test_normalize_spamhaus():
    """
    Spamhaus məlumatlarının normallaşdırılması testi.
    
    CIDR-in 'ip' tipi olaraq map olunduğunu, reason-un tag olaraq
    saxlanıldığını yoxlayır.
    """
    raw = [
        {"cidr": "192.168.1.0/24", "reason": "SBL12345"},
        {"cidr": "10.0.0.0/8", "reason": ""},
    ]
    
    result = normalizer.normalize_spamhaus(raw)
    
    assert len(result) == 2
    assert result[0]["ioc_value"] == "192.168.1.0/24"
    assert result[0]["ioc_type"] == "ip"
    assert result[0]["source_feed"] == "spamhaus"
    assert "SBL12345" in result[0]["tags"]
    assert result[1]["tags"] == []  # boş reason halında boş tags


def test_normalize_all():
    """
    normalize_all() funksiyasının bütün feed-ləri düzgün birləşdirdiyini yoxlayır.
    """
    raw_feeds = {
        "feodo": [{"ip_address": "1.2.3.4", "botnet": "dridex", "last_dns_query": "2024-01-15"}],
        "urlhaus": [{"url": "http://evil.com", "dateadded": "2024-01-15 10:00:00", "threat": "malware"}],
        "malwarebazaar": [{"sha256_hash": "abc123", "first_seen_utc": "2024-01-15 10:00:00"}],
        "spamhaus": [{"cidr": "192.168.1.0/24", "reason": "test"}],
    }
    
    result = normalizer.normalize_all(raw_feeds)
    
    assert len(result) == 4
    
    ioc_types = {r["ioc_type"] for r in result}
    assert ioc_types == {"ip", "url", "hash"}
    
    source_feeds = {r["source_feed"] for r in result}
    assert source_feeds == {"feodo", "urlhaus", "malwarebazaar", "spamhaus"}


def test_normalize_all_unknown_feed_skipped():
    """
    Naməlum feed adının crash yaratmadan skip edildiyini yoxlayır.
    """
    raw_feeds = {
        "unknown_feed": [{"some_field": "some_value"}],
        "feodo": [{"ip_address": "1.2.3.4", "botnet": "test", "last_dns_query": "2024-01-15"}],
    }
    
    result = normalizer.normalize_all(raw_feeds)
    
    assert len(result) == 1
    assert result[0]["source_feed"] == "feodo"


def test_normalize_all_empty_input():
    """
    Boş dict verildikdə boş siyahı qaytardığını yoxlayır.
    """
    result = normalizer.normalize_all({})
    assert result == []
