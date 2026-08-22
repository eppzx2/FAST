"""
CLI (Command Line Interface)

Terminal vasitəsilə TALON IOC Collector-dan istifadə.

Istifadə:
    python cli.py --init-db        # Verilənlər bazasını yarat
    python cli.py --fetch          # Bütün feed-lərdən yığ, normallaşdır, bazaya yaz
    python cli.py --export csv     # CSV olaraq export et
    python cli.py --export json    # JSON olaraq export et
    python cli.py --export both    # Həm CSV, həm JSON export et
    python cli.py --show           # Bazada olan IOC-ları göstər
    python cli.py --count          # IOC sayını göstər
"""

import argparse
import logging
from core import fetchers, normalizer, db, scoring, exporter, wazuh_export

# Logging konfiqurasiyası
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_init_db() -> None:
    """
    Verilənlər bazasını yaradır (mövcud deyilsə).
    
    Returns:
        None
    """
    db.init_database()
    print("✓ Verilənlər bazası hazırdır.")


def run_fetch() -> None:
    """
    Bütün feed-lərdən IOC yığır, normallaşdırır və bazaya yazır.
    
    Axın: fetch_all_feeds() -> normalize_all() -> insert_batch()
    (Dedup və confidence scoring db.insert_ioc() daxilində avtomatik baş verir.)
    
    Returns:
        None
    """
    db.init_database()
    
    print("📡 Feed-lərdən məlumat çəkilir...")
    raw_feeds = fetchers.fetch_all_feeds()
    
    for feed_name, iocs in raw_feeds.items():
        print(f"  • {feed_name}: {len(iocs)} xam qeyd")
    
    print("\n🔄 Normallaşdırılır...")
    normalized = normalizer.normalize_all(raw_feeds)
    print(f"  • Cəmi {len(normalized)} IOC normallaşdırıldı")
    
    print("\n💾 Bazaya yazılır (dedup + scoring avtomatik)...")
    count = db.insert_batch(normalized)
    print(f"  • {count} IOC emal edildi")
    
    total_in_db = db.get_count()
    print(f"\n✓ Tamamlandı. Bazadakı cəmi unikal IOC sayı: {total_in_db}")


def run_export(fmt: str) -> None:
    """
    Bazadakı bütün IOC-ları göstərilən formatda export edir.
    
    Args:
        fmt (str): 'csv', 'json', və ya 'both'
        
    Returns:
        None
    """
    iocs = db.get_all_iocs()
    
    if not iocs:
        print("⚠️ Bazada IOC yoxdur. Əvvəlcə --fetch işə sal.")
        return
    
    if fmt == "csv":
        ok = exporter.export_to_csv(iocs)
        print(f"{'✓' if ok else '✗'} CSV export: sample_output/ioc_export.csv ({len(iocs)} IOC)")
    elif fmt == "json":
        ok = exporter.export_to_json(iocs)
        print(f"{'✓' if ok else '✗'} JSON export: sample_output/ioc_export.json ({len(iocs)} IOC)")
    elif fmt == "both":
        ok = exporter.export_both(iocs)
        print(f"{'✓' if ok else '✗'} CSV+JSON export: sample_output/ ({len(iocs)} IOC)")
    elif fmt == "wazuh":
        stats = wazuh_export.get_export_stats(iocs)
        ok = wazuh_export.export_to_cdb_list(iocs)
        print(
            f"{'✓' if ok else '✗'} Wazuh CDB list export: sample_output/ioc-ips "
            f"({stats['exported']}/{stats['ip_type']} 'ip' tipli IOC, "
            f"cəmi {stats['total']} IOC-dan)"
        )
    else:
        print(f"✗ Naməlum format: '{fmt}'. 'csv', 'json', 'both' və ya 'wazuh' istifadə et.")


def run_show() -> None:
    """
    Bazadakı bütün IOC-ları terminalda cədvəl şəklində göstərir.
    
    Returns:
        None
    """
    iocs = db.get_all_iocs()
    
    if not iocs:
        print("⚠️ Bazada IOC yoxdur. Əvvəlcə --fetch işə sal.")
        return
    
    print(f"\n{'IOC Value':<45} {'Type':<8} {'Feed':<25} {'Score':<6} {'Last Seen'}")
    print("-" * 110)
    
    for ioc in iocs:
        value = str(ioc.get("ioc_value", ""))[:43]
        print(
            f"{value:<45} "
            f"{ioc.get('ioc_type', ''):<8} "
            f"{str(ioc.get('source_feed', ''))[:23]:<25} "
            f"{ioc.get('confidence_score', 0):<6} "
            f"{ioc.get('last_seen', '')}"
        )
    
    print(f"\nCəmi: {len(iocs)} IOC")


def run_count() -> None:
    """
    Bazadakı toplam IOC sayını göstərir.
    
    Returns:
        None
    """
    count = db.get_count()
    print(f"Bazadakı toplam IOC sayı: {count}")


def main():
    """
    CLI əsas funksiyası.
    
    Command line arqumentlərini parse edib müvafiq funksiyaları çağırır.
    Heç bir arqument verilmədikdə köməkçi mesaj göstərir.
    """
    parser = argparse.ArgumentParser(
        description="TALON IOC Collector - Terminal İnterfeysi"
    )
    parser.add_argument("--init-db", action="store_true", help="Verilənlər bazasını yarat")
    parser.add_argument("--fetch", action="store_true", help="Bütün feed-lərdən yığ")
    parser.add_argument("--export", choices=["csv", "json", "both", "wazuh"], help="Export formatı")
    parser.add_argument("--show", action="store_true", help="IOC-ları göstər")
    parser.add_argument("--count", action="store_true", help="IOC sayını göstər")
    
    args = parser.parse_args()
    
    if not any([args.init_db, args.fetch, args.export, args.show, args.count]):
        parser.print_help()
        return
    
    if args.init_db:
        run_init_db()
    
    if args.fetch:
        run_fetch()
    
    if args.export:
        run_export(args.export)
    
    if args.show:
        run_show()
    
    if args.count:
        run_count()


if __name__ == "__main__":
    main()
