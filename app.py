"""
Flask Web Application

Veb vasitəsilə TALON IOC Collector-dan istifadə.

Bu fayl yalnız core/ modulunu çağırır (fetchers, normalizer, db,
scoring, exporter) - heç bir biznes məntiqi burada təkrarlanmır.

Rout-lar:
    GET  /                      # Əsas səhifə (dashboard)
    GET  /api/iocs               # Səhifələnmiş, filtrli IOC siyahısı (JSON)
    POST /api/fetch               # Feed-lərdən yığ, normallaşdır, bazaya yaz
    GET  /api/export?format=csv   # CSV export edib fayl olaraq göndər
    GET  /api/export?format=json  # JSON export edib fayl olaraq göndər
    GET  /api/stats               # Ümumi statistika (tip/feed/score bölgüsü)

Işə salmaq:
    python3 app.py
    -> http://localhost:5000
"""

import logging
import os
from flask import Flask, render_template, jsonify, request, send_file

from core import fetchers, normalizer, db, exporter

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@app.route("/")
def index():
    """
    Əsas səhifə - IOC Collector Dashboard-u render edir.

    Returns:
        str: Render olunmuş HTML (templates/index.html)
    """
    db.init_database()
    return render_template("index.html")


@app.route("/api/iocs")
def get_iocs():
    """
    Bazadakı IOC-ları səhifələnmiş və filtrlənmiş şəkildə JSON olaraq qaytarır.

    Query parametrləri:
        page (int): Səhifə nömrəsi (default 1)
        per_page (int): Səhifə başına sətir sayı (default 50, max 200)
        type (str): 'ip' | 'domain' | 'hash' | 'url' (optional filtr)
        feed (str): feed adı (optional filtr, source_feed daxilində axtarır)
        search (str): ioc_value daxilində alt-mətn axtarışı (optional)

    Returns:
        Response: JSON {items, total, page, per_page, total_pages}
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except (TypeError, ValueError):
        page, per_page = 1, 50

    type_filter = request.args.get("type", "").strip()
    feed_filter = request.args.get("feed", "").strip()
    search = request.args.get("search", "").strip().lower()

    all_iocs = db.get_all_iocs()

    if type_filter:
        all_iocs = [i for i in all_iocs if i.get("ioc_type") == type_filter]
    if feed_filter:
        all_iocs = [i for i in all_iocs if feed_filter in (i.get("source_feed") or "")]
    if search:
        all_iocs = [i for i in all_iocs if search in str(i.get("ioc_value", "")).lower()]

    total = len(all_iocs)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)

    start = (page - 1) * per_page
    end = start + per_page
    items = all_iocs[start:end]

    return jsonify({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
    })


@app.route("/api/fetch", methods=["POST"])
def fetch_feeds():
    """
    Bütün feed-lərdən məlumatı çəkir, normallaşdırır və bazaya əlavə edir.

    Xəta halında (feed əlçatan deyilsə) proqram çökmür, o feed 0 IOC
    ilə nəticələnir və digərləri ilə davam edilir (fetchers.py-dəki
    xəta-toleranslığı sayəsində).

    Returns:
        Response: JSON {status, raw_counts, normalized_count,
                         inserted_count, total_in_db}
    """
    try:
        db.init_database()

        raw_feeds = fetchers.fetch_all_feeds()
        raw_counts = {k: len(v) for k, v in raw_feeds.items()}

        normalized = normalizer.normalize_all(raw_feeds)
        inserted = db.insert_batch(normalized)

        return jsonify({
            "status": "ok",
            "raw_counts": raw_counts,
            "normalized_count": len(normalized),
            "inserted_count": inserted,
            "total_in_db": db.get_count(),
        })
    except Exception as e:
        logger.error(f"/api/fetch xətası: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/export")
def export_iocs():
    """
    IOC-ları CSV və ya JSON olaraq export edib fayl kimi göndərir.

    Query parametrləri:
        format (str): 'csv' və ya 'json' (default 'csv')

    Returns:
        Response: Yüklənə bilən fayl, ya da xəta halında JSON mesajı
    """
    fmt = request.args.get("format", "csv").lower()
    iocs = db.get_all_iocs()

    if not iocs:
        return jsonify({"status": "error", "message": "Bazada IOC yoxdur"}), 400

    if fmt == "csv":
        ok = exporter.export_to_csv(iocs)
        filepath = os.path.join(exporter.EXPORT_DIR, "ioc_export.csv")
        mimetype = "text/csv"
    elif fmt == "json":
        ok = exporter.export_to_json(iocs)
        filepath = os.path.join(exporter.EXPORT_DIR, "ioc_export.json")
        mimetype = "application/json"
    else:
        return jsonify({"status": "error", "message": f"Naməlum format: {fmt}"}), 400

    if not ok or not os.path.exists(filepath):
        return jsonify({"status": "error", "message": "Export uğursuz oldu"}), 500

    return send_file(filepath, mimetype=mimetype, as_attachment=True)


@app.route("/api/stats")
def get_stats():
    """
    Ümumi statistika qaytarır: toplam say, tip üzrə bölgü,
    feed üzrə bölgü, confidence score bölgüsü.

    Returns:
        Response: JSON {total, by_type, by_feed, by_score, feed_status}
    """
    iocs = db.get_all_iocs()

    by_type = {}
    by_score = {"25": 0, "50": 0, "75": 0, "100": 0}
    feed_counts = {"feodo": 0, "urlhaus": 0, "malwarebazaar": 0, "spamhaus": 0}

    for ioc in iocs:
        t = ioc.get("ioc_type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1

        score = ioc.get("confidence_score", 0)
        bucket = str(min(100, max(25, (score // 25) * 25))) if score else "25"
        if bucket in by_score:
            by_score[bucket] += 1

        feeds_in_row = (ioc.get("source_feed") or "").split(",")
        for f in feeds_in_row:
            f = f.strip()
            if f in feed_counts:
                feed_counts[f] += 1

    return jsonify({
        "total": len(iocs),
        "by_type": by_type,
        "by_feed": feed_counts,
        "by_score": by_score,
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
