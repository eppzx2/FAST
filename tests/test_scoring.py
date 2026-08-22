"""
Test Scoring Module

core.scoring modulunun testləri.
"""

import pytest
from core import scoring


def test_calculate_score_single_feed():
    """
    Tək feed-də görünən IOC-un 25 bal aldığını yoxlayır.
    """
    ioc = {"source_feed": "feodo"}
    assert scoring.calculate_score(ioc) == 25


def test_calculate_score_two_feeds():
    """
    İki fərqli feed-də görünən IOC-un 50 bal aldığını yoxlayır.
    """
    ioc = {"source_feed": "feodo,urlhaus"}
    assert scoring.calculate_score(ioc) == 50


def test_calculate_score_three_feeds():
    """
    Üç fərqli feed-də görünən IOC-un 75 bal aldığını yoxlayır.
    """
    ioc = {"source_feed": "feodo,urlhaus,malwarebazaar"}
    assert scoring.calculate_score(ioc) == 75


def test_calculate_score_all_four_feeds():
    """
    Bütün 4 feed-də görünən IOC-un maksimum 100 bal aldığını yoxlayır.
    """
    ioc = {"source_feed": "feodo,urlhaus,malwarebazaar,spamhaus"}
    assert scoring.calculate_score(ioc) == 100


def test_calculate_score_missing_source_feed():
    """
    'source_feed' sahəsi olmadıqda 0 qaytardığını (crash olmadan) yoxlayır.
    """
    ioc = {}
    assert scoring.calculate_score(ioc) == 0


def test_calculate_score_duplicate_feed_names_counted_once():
    """
    Eyni feed adı təkrarlansa belə, bir dəfə sayıldığını yoxlayır
    (məs: "feodo,feodo" -> 1 feed, 25 bal).
    """
    ioc = {"source_feed": "feodo,feodo"}
    assert scoring.calculate_score(ioc) == 25


def test_update_scores_batch():
    """
    Batch score yeniləmənin bütün IOC-ları düzgün yenilədiyini yoxlayır.
    """
    iocs = [
        {"ioc_value": "1.1.1.1", "source_feed": "feodo"},
        {"ioc_value": "2.2.2.2", "source_feed": "feodo,urlhaus"},
    ]
    
    updated = scoring.update_scores_batch(iocs)
    
    assert updated[0]["confidence_score"] == 25
    assert updated[1]["confidence_score"] == 50


def test_update_scores_batch_does_not_mutate_original():
    """
    update_scores_batch-in orijinal siyahını dəyişdirmədiyini yoxlayır.
    """
    original = [{"ioc_value": "1.1.1.1", "source_feed": "feodo"}]
    
    scoring.update_scores_batch(original)
    
    assert "confidence_score" not in original[0]
