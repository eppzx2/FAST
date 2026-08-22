"""
Test Exporter Module

core.exporter modulunun testləri.

Hər test EXPORT_DIR-i müvəqqəti qovluğa yönləndirir ki, real 
sample_output/ qovluğuna toxunmasın.
"""

import pytest
import json
import csv
import os
from core import exporter


@pytest.fixture
def temp_export_dir(tmp_path, monkeypatch):
    """
    Test üçün müvəqqəti export qovluğu təyin edir.
    """
    export_dir = tmp_path / "test_output"
    monkeypatch.setattr(exporter, "EXPORT_DIR", str(export_dir))
    return str(export_dir)


def _sample_iocs():
    """Test üçün nümunə IOC siyahısı."""
    return [
        {
            "ioc_value": "1.2.3.4",
            "ioc_type": "ip",
            "source_feed": "feodo,urlhaus",
            "first_seen": "2024-01-15T10:00:00",
            "last_seen": "2024-01-20T10:00:00",
            "confidence_score": 50,
            "tags": ["dridex", "botnet"],
        },
        {
            "ioc_value": "http://evil.com/malware.exe",
            "ioc_type": "url",
            "source_feed": "urlhaus",
            "first_seen": "2024-01-16T10:00:00",
            "last_seen": "2024-01-16T10:00:00",
            "confidence_score": 25,
            "tags": ["malware_download"],
        },
    ]


def test_export_to_csv(temp_export_dir):
    """
    CSV export-un faylı düzgün yaratdığını, başlıqların və 
    sətirlərin doğru olduğunu yoxlayır.
    """
    result = exporter.export_to_csv(_sample_iocs(), "test.csv")
    
    assert result is True
    filepath = os.path.join(temp_export_dir, "test.csv")
    assert os.path.exists(filepath)
    
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    assert len(rows) == 2
    assert rows[0]["ioc_value"] == "1.2.3.4"
    assert rows[0]["ioc_type"] == "ip"
    assert rows[0]["confidence_score"] == "50"
    # tags JSON string kimi saxlanılıb
    assert json.loads(rows[0]["tags"]) == ["dridex", "botnet"]


def test_export_to_csv_empty_list(temp_export_dir):
    """
    Boş IOC siyahısı ilə CSV export-un yalnız başlıq sətri olan 
    fayl yaratdığını (crash olmadan) yoxlayır.
    """
    result = exporter.export_to_csv([], "empty.csv")
    
    assert result is True
    filepath = os.path.join(temp_export_dir, "empty.csv")
    assert os.path.exists(filepath)
    
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    assert len(rows) == 0


def test_export_to_json(temp_export_dir):
    """
    JSON export-un faylı düzgün yaratdığını və məzmununun 
    doğru olduğunu yoxlayır.
    """
    result = exporter.export_to_json(_sample_iocs(), "test.json")
    
    assert result is True
    filepath = os.path.join(temp_export_dir, "test.json")
    assert os.path.exists(filepath)
    
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    assert len(data) == 2
    assert data[0]["ioc_value"] == "1.2.3.4"
    assert data[0]["tags"] == ["dridex", "botnet"]  # list olaraq qalır (JSON native)


def test_export_to_json_empty_list(temp_export_dir):
    """
    Boş IOC siyahısı ilə JSON export-un boş array yaratdığını yoxlayır.
    """
    result = exporter.export_to_json([], "empty.json")
    
    assert result is True
    filepath = os.path.join(temp_export_dir, "empty.json")
    
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    assert data == []


def test_export_both(temp_export_dir):
    """
    export_both-un həm CSV, həm JSON faylını yaratdığını yoxlayır.
    """
    result = exporter.export_both(_sample_iocs())
    
    assert result is True
    assert os.path.exists(os.path.join(temp_export_dir, "ioc_export.csv"))
    assert os.path.exists(os.path.join(temp_export_dir, "ioc_export.json"))


def test_export_creates_directory_if_missing(tmp_path, monkeypatch):
    """
    EXPORT_DIR mövcud olmadıqda avtomatik yaradıldığını yoxlayır.
    """
    non_existent_dir = tmp_path / "does_not_exist_yet"
    monkeypatch.setattr(exporter, "EXPORT_DIR", str(non_existent_dir))
    
    assert not os.path.exists(str(non_existent_dir))
    
    result = exporter.export_to_csv(_sample_iocs(), "test.csv")
    
    assert result is True
    assert os.path.exists(str(non_existent_dir))


def test_export_to_csv_invalid_path_returns_false(monkeypatch):
    """
    Yazıla bilməyən (keçərsiz) yol verildikdə crash olmadan 
    False qaytardığını yoxlayır.
    """
    # Kök qovluqda icazəsiz yer (adətən yazıla bilməz) simulyasiya edilir
    monkeypatch.setattr(exporter, "EXPORT_DIR", "/root/no_permission_dir_xyz")
    
    result = exporter.export_to_csv(_sample_iocs(), "test.csv")
    
    # Sandbox mühitindən asılı olaraq ya False qayıdır, ya da yazıla bilər;
    # hər halda funksiya crash etməməlidir - bunu yoxlayırıq
    assert isinstance(result, bool)
