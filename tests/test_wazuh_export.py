"""
Test Wazuh Export Module

core.wazuh_export modulunun testləri.
"""

import pytest
import os
from core import wazuh_export


@pytest.fixture
def temp_output_dir(tmp_path):
    """Müvəqqəti çıxış qovluğu."""
    return str(tmp_path / "test_cdb_output")


def _sample_iocs():
    """Test üçün qarışıq tipli IOC siyahısı (ip, url, hash)."""
    return [
        {"ioc_value": "1.2.3.4", "ioc_type": "ip", "confidence_score": 75},
        {"ioc_value": "5.6.7.8", "ioc_type": "ip", "confidence_score": 25},
        {"ioc_value": "192.168.1.0/24", "ioc_type": "ip", "confidence_score": 50},
        {"ioc_value": "http://evil.com", "ioc_type": "url", "confidence_score": 100},
        {"ioc_value": "abc123hash", "ioc_type": "hash", "confidence_score": 100},
    ]


def test_export_to_cdb_list_only_ip_type(temp_output_dir):
    """
    Yalnız 'ip' tipli IOC-ların CDB list-ə daxil edildiyini yoxlayır
    (url/hash tipli IOC-lar xaric edilməlidir).
    """
    result = wazuh_export.export_to_cdb_list(_sample_iocs(), output_dir=temp_output_dir)

    assert result is True
    filepath = os.path.join(temp_output_dir, "ioc-ips")

    with open(filepath, "r") as f:
        content = f.read()

    assert "1.2.3.4:1" in content
    assert "5.6.7.8:1" in content
    assert "192.168.1.0/24:1" in content
    assert "evil.com" not in content
    assert "abc123hash" not in content


def test_export_to_cdb_list_min_confidence_filter(temp_output_dir):
    """
    min_confidence parametrinin aşağı etibarlılıqlı IOC-ları
    süzgəcdən keçirdiyini yoxlayır.
    """
    result = wazuh_export.export_to_cdb_list(
        _sample_iocs(), output_dir=temp_output_dir, min_confidence=50
    )

    assert result is True
    filepath = os.path.join(temp_output_dir, "ioc-ips")

    with open(filepath, "r") as f:
        content = f.read()

    assert "1.2.3.4:1" in content  # 75 >= 50
    assert "192.168.1.0/24:1" in content  # 50 >= 50
    assert "5.6.7.8:1" not in content  # 25 < 50


def test_export_to_cdb_list_no_duplicates(temp_output_dir):
    """
    Eyni IP iki dəfə verilsə belə, CDB list-də bir dəfə göründüyünü yoxlayır.
    """
    iocs = [
        {"ioc_value": "1.2.3.4", "ioc_type": "ip", "confidence_score": 50},
        {"ioc_value": "1.2.3.4", "ioc_type": "ip", "confidence_score": 50},
    ]

    wazuh_export.export_to_cdb_list(iocs, output_dir=temp_output_dir)
    filepath = os.path.join(temp_output_dir, "ioc-ips")

    with open(filepath, "r") as f:
        lines = [l for l in f.read().splitlines() if l]

    assert len(lines) == 1


def test_export_to_cdb_list_empty_input(temp_output_dir):
    """
    Boş IOC siyahısı ilə crash olmadan boş fayl yaratdığını yoxlayır.
    """
    result = wazuh_export.export_to_cdb_list([], output_dir=temp_output_dir)

    assert result is True
    filepath = os.path.join(temp_output_dir, "ioc-ips")
    assert os.path.exists(filepath)


def test_export_to_cdb_list_no_ip_type_present(temp_output_dir):
    """
    Yalnız url/hash tipli IOC-lar verildikdə (heç bir 'ip' yoxdur)
    crash olmadan boş fayl yaratdığını yoxlayır.
    """
    iocs = [
        {"ioc_value": "http://evil.com", "ioc_type": "url", "confidence_score": 100},
    ]

    result = wazuh_export.export_to_cdb_list(iocs, output_dir=temp_output_dir)

    assert result is True
    filepath = os.path.join(temp_output_dir, "ioc-ips")
    with open(filepath, "r") as f:
        assert f.read() == ""


def test_get_export_stats():
    """
    get_export_stats-ın düzgün say statistikası qaytardığını yoxlayır.
    """
    stats = wazuh_export.get_export_stats(_sample_iocs(), min_confidence=50)

    assert stats["total"] == 5
    assert stats["ip_type"] == 3
    assert stats["exported"] == 2  # yalnız 75 və 50 >= 50
    assert stats["filtered_out"] == 1  # 25 < 50


def test_get_export_stats_empty_input():
    """
    Boş siyahı ilə sıfır statistikası qaytardığını yoxlayır.
    """
    stats = wazuh_export.get_export_stats([])

    assert stats == {"total": 0, "ip_type": 0, "exported": 0, "filtered_out": 0}
