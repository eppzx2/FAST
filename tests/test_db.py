"""
Test Database Module

core.db modulunun testləri.

Hər test öz müvəqqəti (temporary) SQLite faylı ilə işləyir ki,
testlər bir-birinə təsir etməsin və real ioc_database.db toxunulmaz qalsın.
"""

import pytest
from core import db


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """
    Test üçün əqici (temporary) verilənlər bazası yaradır.
    
    db.DB_PATH-i müvəqqəti fayla yönləndirir ki, testlər real 
    bazaya toxunmasın. Hər test üçün təmiz, boş baza təmin edir.
    """
    temp_path = tmp_path / "test_ioc.db"
    monkeypatch.setattr(db, "DB_PATH", str(temp_path))
    db.init_database()
    return str(temp_path)


def _sample_ioc(value="1.2.3.4", ioc_type="ip", feed="feodo"):
    """Test üçün nümunə normallaşdırılmış IOC yaradan köməkçi funksiya."""
    return {
        "ioc_value": value,
        "ioc_type": ioc_type,
        "source_feed": feed,
        "first_seen": "2024-01-15T10:00:00",
        "last_seen": "2024-01-15T10:00:00",
        "tags": ["test_tag"],
    }


def test_init_database(temp_db):
    """
    Bazanın başlanğıc yaradılması testi.
    
    Cədvəlin yaradıldığını və ikinci çağırışın xəta vermədiyini yoxlayır.
    """
    # İkinci çağırış xəta verməməlidir (CREATE TABLE IF NOT EXISTS)
    db.init_database()
    
    assert db.get_count() == 0


def test_insert_ioc(temp_db):
    """
    IOC əlavə etmə testi.
    """
    ioc = _sample_ioc()
    result = db.insert_ioc(ioc)
    
    assert result is True
    assert db.get_count() == 1
    
    stored = db.get_ioc("1.2.3.4", "ip")
    assert stored is not None
    assert stored["ioc_value"] == "1.2.3.4"
    assert stored["confidence_score"] == 25  # 1 feed * 25
    assert stored["tags"] == ["test_tag"]


def test_insert_ioc_missing_required_field(temp_db):
    """
    Tələb olunan sahə çatışmadıqda insert_ioc-un False qaytardığını 
    (crash olmadan) yoxlayır.
    """
    incomplete_ioc = {"ioc_value": "1.2.3.4"}  # ioc_type, source_feed vs. yoxdur
    result = db.insert_ioc(incomplete_ioc)
    
    assert result is False
    assert db.get_count() == 0


def test_dedup_insert(temp_db):
    """
    Deduplication testi - eyni IOC iki dəfə əlavə etməməliyik.
    
    Eyni (ioc_value, ioc_type) ilə ikinci dəfə insert edildikdə:
    - Cəmi qeyd sayı 1 olaraq qalmalı (yeni sətir yaranmamalı)
    - last_seen yenilənməli
    - source_feed-lər birləşdirilməli
    """
    ioc1 = _sample_ioc(feed="feodo")
    ioc1["last_seen"] = "2024-01-15T10:00:00"
    
    ioc2 = _sample_ioc(feed="urlhaus")
    ioc2["last_seen"] = "2024-01-20T15:00:00"  # daha sonrakı tarix
    
    db.insert_ioc(ioc1)
    db.insert_ioc(ioc2)
    
    # Cəmi sayı 1 olmalı - yeni sətir yaranmayıb
    assert db.get_count() == 1
    
    stored = db.get_ioc("1.2.3.4", "ip")
    assert stored["last_seen"] == "2024-01-20T15:00:00"
    assert "feodo" in stored["source_feed"]
    assert "urlhaus" in stored["source_feed"]
    assert stored["confidence_score"] == 50  # 2 fərqli feed * 25


def test_get_ioc(temp_db):
    """
    IOC sorğu etmə testi.
    
    Mövcud IOC-un düzgün qaytarıldığını, mövcud olmayanın None 
    qaytardığını yoxlayır.
    """
    db.insert_ioc(_sample_ioc())
    
    found = db.get_ioc("1.2.3.4", "ip")
    assert found is not None
    assert found["ioc_value"] == "1.2.3.4"
    
    not_found = db.get_ioc("9.9.9.9", "ip")
    assert not_found is None


def test_get_all_iocs(temp_db):
    """
    Bütün IOC-ları sorğu etmə testi.
    """
    db.insert_ioc(_sample_ioc(value="1.1.1.1"))
    db.insert_ioc(_sample_ioc(value="2.2.2.2"))
    db.insert_ioc(_sample_ioc(value="hash123", ioc_type="hash", feed="malwarebazaar"))
    
    all_iocs = db.get_all_iocs()
    
    assert len(all_iocs) == 3
    values = {ioc["ioc_value"] for ioc in all_iocs}
    assert values == {"1.1.1.1", "2.2.2.2", "hash123"}


def test_insert_batch(temp_db):
    """
    Batch insert testi - çoxlu IOC-un düzgün əlavə edildiyini yoxlayır.
    """
    iocs = [
        _sample_ioc(value="1.1.1.1"),
        _sample_ioc(value="2.2.2.2"),
        _sample_ioc(value="1.1.1.1"),  # dublikat - update olunmalı, yeni sətir yox
    ]
    
    count = db.insert_batch(iocs)
    
    assert count == 3  # 3 uğurlu əməliyyat (2 insert + 1 update)
    assert db.get_count() == 2  # amma cəmi 2 unikal qeyd


def test_update_ioc(temp_db):
    """
    IOC yeniləmə testi.
    """
    db.insert_ioc(_sample_ioc())
    
    result = db.update_ioc("1.2.3.4", "ip", "2024-02-01T00:00:00", "spamhaus")
    assert result is True
    
    updated = db.get_ioc("1.2.3.4", "ip")
    assert updated["last_seen"] == "2024-02-01T00:00:00"
    assert updated["source_feed"] == "spamhaus"


def test_update_ioc_not_found(temp_db):
    """
    Mövcud olmayan IOC yeniləməyə cəhd edildikdə False qaytardığını yoxlayır.
    """
    result = db.update_ioc("9.9.9.9", "ip", "2024-02-01T00:00:00", "feodo")
    assert result is False


def test_delete_ioc(temp_db):
    """
    IOC silmə testi.
    """
    db.insert_ioc(_sample_ioc())
    assert db.get_count() == 1
    
    result = db.delete_ioc("1.2.3.4", "ip")
    assert result is True
    assert db.get_count() == 0
    assert db.get_ioc("1.2.3.4", "ip") is None


def test_delete_ioc_not_found(temp_db):
    """
    Mövcud olmayan IOC silməyə cəhd edildikdə False qaytardığını yoxlayır.
    """
    result = db.delete_ioc("9.9.9.9", "ip")
    assert result is False


def test_get_count(temp_db):
    """
    IOC sayı sorğusu testi.
    """
    assert db.get_count() == 0
    
    db.insert_ioc(_sample_ioc(value="1.1.1.1"))
    assert db.get_count() == 1
    
    db.insert_ioc(_sample_ioc(value="2.2.2.2"))
    assert db.get_count() == 2
