#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import hashlib
import difflib
import html as html_lib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple, Set

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None
try:
    import feedparser
except ModuleNotFoundError:
    raise SystemExit(
        "Missing dependency: feedparser\n"
        "Install with: python -m pip install feedparser\n"
        "Or install all deps: python -m pip install -r requirements.txt"
    )

try:
    import requests
except ModuleNotFoundError:
    raise SystemExit(
        "Missing dependency: requests\n"
        "Install with: python -m pip install requests\n"
        "Or install all deps: python -m pip install -r requirements.txt"
    )

try:
    from bs4 import BeautifulSoup
except ModuleNotFoundError:
    raise SystemExit(
        "Missing dependency: beautifulsoup4\n"
        "Install with: python -m pip install beautifulsoup4\n"
        "Or install all deps: python -m pip install -r requirements.txt"
    )
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3


# =========================
# Time / Globals
# =========================
if ZoneInfo is not None:
    try:
        KST = ZoneInfo("Asia/Seoul")
    except Exception:
        # Windows/Python 환경에서 tzdata 미설치 시 fallback
        KST = timezone(timedelta(hours=9))
else:
    try:
        import pytz  # type: ignore

        KST = pytz.timezone("Asia/Seoul")
    except Exception:
        KST = timezone(timedelta(hours=9))

DOCS_DIR = "docs"
INDEX_HTML = os.path.join(DOCS_DIR, "index.html")
STATE_JSON = os.path.join(DOCS_DIR, "site_state.json")
MONITOR_MD = os.path.join(DOCS_DIR, "site_monitor.md")
MONITOR_SUMMARY_JSON = os.path.join(DOCS_DIR, "monitor_summary.json")

SITE_STATE_URL = os.getenv("SITE_STATE_URL", "").strip()  # raw gh-pages json (optional)


# =========================
# HTTP Session (retry/backoff)
# =========================
def env_bool(name: str, default: bool = True) -> bool:
    v = os.getenv(name, "").strip().lower()
    if not v:
        return default
    return v in {"1", "true", "yes", "y", "on"}


def build_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        status=4,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (compatible; drug-news-briefing/1.0; +https://github.com/)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        }
    )

    # TLS options for local environments with SSL interception/proxy issues.
    ca_bundle = os.getenv("REQUESTS_CA_BUNDLE", "").strip()
    if ca_bundle:
        s.verify = ca_bundle
    else:
        s.verify = env_bool("SSL_VERIFY", True)
    if s.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return s


# =========================
# Helpers
# =========================
def ensure_docs_dir() -> None:
    os.makedirs(DOCS_DIR, exist_ok=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_get_json(session: requests.Session, url: str, timeout: int = 20) -> Optional[dict]:
    """Fetch JSON with the shared retry-enabled session."""
    if not url:
        return None
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def load_prev_state(session: requests.Session) -> dict:
    """
    Priority:
      1) SITE_STATE_URL (gh-pages raw json)
      2) local docs/site_state.json
      3) empty dict

    If structure is {"meta":..., "sites":{...}}, return sites.
    """
    prev = safe_get_json(session, SITE_STATE_URL) if SITE_STATE_URL else None
    if isinstance(prev, dict):
        return prev.get("sites", prev)

    try:
        with open(STATE_JSON, "r", encoding="utf-8") as f:
            obj = json.load(f)
            return obj.get("sites", obj)
    except Exception:
        return {}


def write_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def shorten(s: str, max_len: int = 70) -> str:
    s = (s or "").strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."

def clean_token(s: str) -> str:
    """Normalize HTML fragments into stable token text."""
    s = html_lib.unescape(s or "")
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s
    
# =========================
# News Briefing
# =========================
def build_google_news_rss_url(query: str, hl: str = "ko", gl: str = "KR", ceid: str = "KR:ko") -> str:
    from urllib.parse import quote_plus

    return "https://news.google.com/rss/search?q=" + quote_plus(query) + f"&hl={hl}&gl={gl}&ceid={ceid}"


def normalize_title(title: str) -> str:
    t = title.strip()
    # Remove trailing publisher part in Google News title: "... - Publisher"
    t = re.sub(r"\s+-\s+[^-]{2,40}$", "", t).strip()
    # Normalize common quote/bracket symbols
    t = re.sub(r"[\[\]\(\)\"'“”‘’]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def extract_publisher(raw_title: str) -> str:
    m = re.search(r"\s+-\s+([^-]{2,40})$", raw_title.strip())
    return m.group(1).strip() if m else ""


NEWS_STYLE_NOISE = [
    "단독", "속보", "충격", "논란", "파문", "비판", "급락", "급등",
    "초비상", "위기", "재앙", "대참사", "경악", "소름", "아찔",
]
COMMON_FILLERS = [
    "이다", "했다", "관련", "이유", "사실", "추정", "가능성",
    "화면", "공식", "최근", "오늘", "어제", "내일",
]


def normalize_title_strong(raw_title: str) -> str:
    """Normalize title text for robust de-duplication and clustering."""
    t = normalize_title(raw_title)

    # Normalize punctuation and separators
    t = re.sub(r"[\"'“”‘’]", " ", t)
    t = re.sub(r"[|/:;]", " ", t)

    # Normalize ordinal spacing
    t = re.sub(r"\b2\s*차\b", "2차", t)
    t = re.sub(r"\b3\s*차\b", "3차", t)
    t = re.sub(r"\b4\s*차\b", "4차", t)
    t = re.sub(r"\b(\d+)\s*차\b", r"\1차", t)

    # Remove clickbait / filler terms
    for p in NEWS_STYLE_NOISE:
        t = re.sub(rf"\b{re.escape(p)}\b", " ", t, flags=re.I)
    for p in COMMON_FILLERS:
        t = re.sub(rf"\b{re.escape(p)}\b", " ", t, flags=re.I)

    t = re.sub(r"\s+", " ", t).strip()
    return t


GENERIC_STOPWORDS = set(
    [
        "및", "다시", "이후", "관련", "이유", "사실", "추정", "가능성",
        "오늘", "어제", "내일", "이번", "지역", "최근", "현재", "즉시",
        "논란", "파문", "충격", "속보", "단독", "아찔", "무산",
        "공식", "화면", "급등", "급락", "레전드",
    ]
)
KOREAN_PARTICLES = ("은", "는", "이", "가", "을", "를", "의", "에서", "으로", "와", "과", "도", "만")


def strip_korean_particle(token: str) -> str:
    """Trim common Korean particles from long Korean tokens."""
    if not token:
        return token
    if re.fullmatch(r"[가-힣]{3,}", token):
        for p in KOREAN_PARTICLES:
            if token.endswith(p) and len(token) > len(p) + 1:
                return token[: -len(p)]
    return token


def core_tokens(raw_title: str) -> List[str]:
    s = normalize_title_strong(raw_title).lower()
    toks = re.findall(r"[0-9A-Za-z가-힣]+", s)

    out: List[str] = []
    for t in toks:
        if len(t) <= 1:
            continue
        if t in GENERIC_STOPWORDS:
            continue
        t = strip_korean_particle(t)
        if len(t) <= 1:
            continue
        out.append(t)

    # Remove duplicates while preserving order
    seen: Set[str] = set()
    uniq: List[str] = []
    for t in out:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
    return uniq


def anchor_tokens(tokens: List[str]) -> Set[str]:
    """High-signal tokens (numbers, mixed tokens, proper-like words)."""
    anchors: Set[str] = set()
    for t in tokens:
        if t in GENERIC_STOPWORDS:
            continue
        if re.fullmatch(r"\d+", t):
            anchors.add(t)
            continue
        if re.search(r"[0-9]", t) and re.search(r"[A-Za-z가-힣]", t):
            anchors.add(t)
            continue
        if re.fullmatch(r"[A-Za-z]{3,}", t):
            anchors.add(t)
            continue
        if re.fullmatch(r"[가-힣]{3,}", t):
            anchors.add(t)
            continue
    return anchors


def jaccard(sa: Set[str], sb: Set[str]) -> float:
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def make_features(item: dict) -> dict:
    raw = item["raw_title"]
    norm = normalize_title_strong(raw)
    core = core_tokens(raw)
    anchors = anchor_tokens(core)
    nums = set(re.findall(r"\b\d+\b", norm))
    sorted_core_str = " ".join(sorted(core))
    return {
        "norm": norm,
        "core": core,
        "core_set": set(core),
        "anchors": anchors,
        "nums": nums,
        "sorted_core_str": sorted_core_str,
        "hash": sha256_hex(norm),
    }


def similarity_score(fa: dict, fb: dict) -> float:
    """
    0~1 event similarity score
    - core jaccard
    - anchor jaccard (high weight)
    - sequence ratio of token-sorted string
    - number overlap bonus
    """
    j_core = jaccard(fa["core_set"], fb["core_set"])
    j_anchor = jaccard(fa["anchors"], fb["anchors"])
    seq = difflib.SequenceMatcher(None, fa["sorted_core_str"], fb["sorted_core_str"]).ratio()

    base = max(j_anchor, j_core * 0.92, seq * 0.98)

    if fa["nums"] and fb["nums"]:
        j_num = len(fa["nums"] & fb["nums"]) / max(1, len(fa["nums"] | fb["nums"]))
        base = min(1.0, base + 0.10 * j_num)

    return base


def cluster_news_events(items: List[dict]) -> List[dict]:
    """
    Cluster news into event groups.
    - exact hash dedup first
    - anchor-based candidate search + similarity score
    - second merge pass to merge split clusters
    """
    # ---- 1) exact dedup by normalized-title hash ----
    by_hash: Dict[str, dict] = {}
    for it in items:
        f = make_features(it)
        h = f["hash"]
        if h not in by_hash:
            by_hash[h] = it
        else:
            # keep newer item
            if it.get("published_ts", 0) > by_hash[h].get("published_ts", 0):
                by_hash[h] = it

    dedup_stage1 = list(by_hash.values())
    dedup_stage1.sort(key=lambda x: x.get("published_ts", 0), reverse=True)

    # ---- 2) incremental clustering with inverted index ----
    clusters: List[dict] = []
    inv: Dict[str, Set[int]] = {}  # token -> cluster_ids

    def add_to_inv(cid: int, toks: Set[str]) -> None:
        for t in toks:
            inv.setdefault(t, set()).add(cid)

    THRESH_WITH_ANCHOR = 0.50
    THRESH_NO_ANCHOR = 0.70

    for it in dedup_stage1:
        fi = make_features(it)

        cand: Set[int] = set()
        for t in list(fi["anchors"])[:8]:
            cand |= inv.get(t, set())
        for n in list(fi["nums"])[:4]:
            cand |= inv.get(n, set())

        if not cand:
            # If no anchor hit, compare only recent clusters for speed.
            cand = set(range(max(0, len(clusters) - 25), len(clusters)))

        best_cid = -1
        best_score = 0.0

        for cid in cand:
            c = clusters[cid]
            s = similarity_score(fi, c["rep_feat"])
            if s > best_score:
                best_score = s
                best_cid = cid

        if best_cid >= 0:
            c = clusters[best_cid]
            anchor_overlap = len(fi["anchors"] & c["anchor_union"])
            num_overlap = len(fi["nums"] & c["num_union"])
            thresh = THRESH_WITH_ANCHOR if (anchor_overlap > 0 or num_overlap > 0) else THRESH_NO_ANCHOR

            if best_score >= thresh:
                # merge
                if it.get("published_ts", 0) > c["rep"].get("published_ts", 0):
                    c["others"].append(c["rep"])
                    c["rep"] = it
                    c["rep_feat"] = fi
                else:
                    c["others"].append(it)

                c["count"] += 1
                new_anchors = fi["anchors"] - c["anchor_union"]
                new_nums = fi["nums"] - c["num_union"]
                c["anchor_union"] |= fi["anchors"]
                c["num_union"] |= fi["nums"]
                add_to_inv(best_cid, new_anchors | new_nums)
                continue

        # new cluster
        cid = len(clusters)
        clusters.append(
            {
                "rep": it,
                "rep_feat": fi,
                "others": [],
                "count": 1,
                "anchor_union": set(fi["anchors"]),
                "num_union": set(fi["nums"]),
            }
        )
        add_to_inv(cid, set(fi["anchors"]) | set(fi["nums"]))

    # ---- 3) merge pass ----
    merged: List[dict] = []
    for c in sorted(clusters, key=lambda x: x["rep"].get("published_ts", 0), reverse=True):
        placed = False
        for m in merged:
            s = similarity_score(c["rep_feat"], m["rep_feat"])
            anchor_overlap = len(c["anchor_union"] & m["anchor_union"])
            num_overlap = len(c["num_union"] & m["num_union"])
            thresh = THRESH_WITH_ANCHOR if (anchor_overlap > 0 or num_overlap > 0) else THRESH_NO_ANCHOR

            if s >= thresh:
                if c["rep"].get("published_ts", 0) > m["rep"].get("published_ts", 0):
                    m["others"].append(m["rep"])
                    m["rep"] = c["rep"]
                    m["rep_feat"] = c["rep_feat"]

                m["others"].extend(c["others"])
                m["count"] += c["count"]
                m["anchor_union"] |= c["anchor_union"]
                m["num_union"] |= c["num_union"]
                placed = True
                break
        if not placed:
            merged.append(c)

    merged.sort(key=lambda x: x["rep"].get("published_ts", 0), reverse=True)

    out = []
    for c in merged:
        out.append(
            {
                "rep": c["rep"],
                "others": c["others"],
                "count": c["count"],
                "cluster_key": sha256_hex(c["rep_feat"]["norm"]),
            }
        )
    return out


def collect_news_last_24h(session: requests.Session) -> Tuple[List[dict], dict]:
    now_kst = datetime.now(KST)
    since_kst = now_kst - timedelta(hours=24)

    query = "(마약 OR 마약류 OR 마약성 OR 향정) AND (적발 OR 검거 OR 단속 OR 밀수 OR 유통 OR 압수)"
    url = build_google_news_rss_url(query)

    feed_text = ""
    try:
        r = session.get(url, timeout=20)
        if r.status_code == 200:
            feed_text = r.text
    except Exception:
        feed_text = ""

    feed = feedparser.parse(feed_text if feed_text else url)

    items: List[dict] = []
    for e in feed.entries:
        raw_title = getattr(e, "title", "").strip()
        link = getattr(e, "link", "").strip()

        published_dt_utc = None
        if getattr(e, "published_parsed", None):
            published_dt_utc = datetime(*e.published_parsed[:6], tzinfo=timezone.utc)
        elif getattr(e, "updated_parsed", None):
            published_dt_utc = datetime(*e.updated_parsed[:6], tzinfo=timezone.utc)

        if not published_dt_utc:
            continue

        published_kst = published_dt_utc.astimezone(KST)
        if published_kst < since_kst:
            continue

        items.append(
            {
                "title": normalize_title(raw_title),
                "raw_title": raw_title,
                "publisher": extract_publisher(raw_title),
                "link": link,
                "published_kst": published_kst.isoformat(timespec="minutes"),
                "published_ts": published_kst.timestamp(),
            }
        )

    items.sort(key=lambda x: x["published_ts"], reverse=True)
    clusters = cluster_news_events(items)

    stats = {
        "collected": len(items),
        "events": len(clusters),
        "since_kst": since_kst.isoformat(timespec="minutes"),
        "now_kst": now_kst.isoformat(timespec="minutes"),
        "rss_url": url,
    }
    return clusters, stats


def render_news_html(event_clusters: List[dict], stats: dict) -> str:
    """
    - 이벤트 단위로 대표 기사만 노출
    - 추가 기사 목록(details)은 표시하지 않음
    """
    if not event_clusters:
        return "<p>최근 24시간 기사 수집 결과가 없습니다.</p>"

    collected = int(stats.get("collected", 0) or 0)
    events = int(stats.get("events", 0) or 0)

    blocks: List[str] = []
    for idx, c in enumerate(event_clusters, start=1):
        rep = c["rep"]
        extra_n = len(c.get("others", []) or [])

        pub = f"<span class='meta'>[{escape_html(rep.get('publisher',''))}]</span> " if rep.get("publisher") else ""
        ts = f"<span class='meta'>{escape_html(rep.get('published_kst',''))}</span>"

        badge_extra = f" <span class='badge small'>+{extra_n}건</span>" if extra_n else ""

        head = (
            f"<div class='event'>"
            f"<div class='event-head'>"
            f"<span class='event-no'>[이벤트 {idx}]</span> "
            f"{pub}<a href='{escape_attr(rep.get('link',''))}' target='_blank' rel='noopener noreferrer'>"
            f"{escape_html(rep.get('title',''))}</a> {ts}"
            f"{badge_extra}"
            f"</div>"
            f"</div>"
        )
        blocks.append(head)

    return (
        f"<div class='kpi'>"
        f"<span class='badge'>기사 {collected}건</span>"
        f"<span class='badge'>이벤트 {events}개</span>"
        f"</div>"
        f"{''.join(blocks)}"
    )


# =========================
# Site Monitoring
# =========================
@dataclass
class MonitorSpec:
    key: str
    name: str
    url: str
    extractor: Callable[[str], List[str]]
    fallback_extractor: Optional[Callable[[str], List[str]]] = None
    soften_dates: bool = True
    use_playwright: bool = False  # Fallback to Playwright when requests extraction fails.
    keep_jsonld: bool = False     # Keep JSON-LD scripts during normalization.


def normalize_html(html: str, soften_dates: bool = True, keep_jsonld: bool = False) -> str:
    soup = BeautifulSoup(html, "html.parser")

    # Remove style/noscript
    for tag in soup(["style", "noscript"]):
        tag.decompose()

    # Script handling:
    # - default: remove all
    # - keep_jsonld=True: keep application/ld+json only
    for tag in soup.find_all("script"):
        if keep_jsonld:
            typ = (tag.get("type") or "").lower().strip()
            if typ == "application/ld+json":
                continue
        tag.decompose()

    text = str(soup)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"([?&](v|t|timestamp|cache|cb)=)[^&\"'>]+", r"\1", text, flags=re.I)

    if soften_dates:
        text = re.sub(r"\b20\d{2}[-/.]\d{1,2}[-/.]\d{1,2}\b", "DATE", text)
        text = re.sub(r"\b1[6-9]\d{8,}\b", "EPOCH", text)

    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_by_regex_list(normalized_html: str, patterns: List[str], max_tokens: int = 120) -> List[str]:
    tokens: List[str] = []
    for pat in patterns:
        found = re.findall(pat, normalized_html, flags=re.I)
        for x in found:
            if isinstance(x, tuple):
                x = " ".join([p for p in x if p])
            x = str(x).strip()
            if x:
                tokens.append(x)

    uniq = []
    seen = set()
    for t in tokens:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
        if len(uniq) >= max_tokens:
            break
    return uniq


def extractor_swgdrug_additional_resources_3_5(normalized_html: str) -> List[str]:
    """
    Parse SWGDRUG "Additional Resources":
    3) SWGDRUG Recommendations Version ...
    5) Searchable Mass Spectral Library Version ...
    Return concise token summaries.
    """
    soup = BeautifulSoup(normalized_html, "html.parser")
    text = soup.get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()

    tokens: List[str] = []

    # 3) SWGDRUG Recommendations Version X.X was approved on Month dd, yyyy
    m3 = re.search(
        r"SWGDRUG Recommendations\s*Version\s*(\d+(?:\.\d+)*)\s*was approved on\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})",
        text,
        flags=re.I,
    )
    if m3:
        ver = m3.group(1).strip()
        date_raw = m3.group(2).strip()
        tokens.append(f"SWGDRUG Recommendations v{ver} (approved {date_raw})")

    # 5) Searchable Mass Spectral Library Version X.X (dated Month dd, yyyy)
    m5 = re.search(
        r"Searchable Mass Spectral Library\s*Version\s*(\d+(?:\.\d+)*)\s*\(dated\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})\)",
        text,
        flags=re.I,
    )
    if m5:
        ver = m5.group(1).strip()
        date_raw = m5.group(2).strip()
        tokens.append(f"SWGDRUG MS Library v{ver} (dated {date_raw})")

    # fallback: version-only extraction
    if not tokens:
        m3b = re.search(r"SWGDRUG Recommendations\s*Version\s*(\d+(?:\.\d+)*)", text, flags=re.I)
        if m3b:
            tokens.append(f"SWGDRUG Recommendations v{m3b.group(1).strip()}")
        m5b = re.search(r"Searchable Mass Spectral Library\s*Version\s*(\d+(?:\.\d+)*)", text, flags=re.I)
        if m5b:
            tokens.append(f"SWGDRUG MS Library v{m5b.group(1).strip()}")

    return tokens[:6]

def _csl_date_from_8digits_dmy(v8: str) -> Optional[str]:
    """
    Parse 8-digit CSL versions as DMY(DDMMYYYY) into YYYY-MM-DD.
    - If DMY is invalid, try YYYYMMDD.
    - MMDDYYYY is intentionally not parsed.
    """
    digits = re.sub(r"\D", "", v8 or "")
    if len(digits) != 8:
        return None

    # 1) DMY: DDMMYYYY
    d = int(digits[0:2])
    m = int(digits[2:4])
    y = int(digits[4:8])
    try:
        dt = datetime(y, m, d)
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        pass

    # 2) fallback YYYYMMDD
    y2 = int(digits[0:4])
    m2 = int(digits[4:6])
    d2 = int(digits[6:8])
    try:
        dt2 = datetime(y2, m2, d2)
        return dt2.strftime("%Y-%m-%d")
    except ValueError:
        return None


def _format_csl_version(v: str) -> str:
    """
    Format CSL version text.
    - If 8 digits and valid DMY, return YYYY-MM-DD.
    - Otherwise return original text.
    """
    v = (v or "").strip()
    digits = re.sub(r"\D", "", v)

    if len(digits) == 8:
        d = int(digits[0:2])
        m = int(digits[2:4])
        y = int(digits[4:8])
        try:
            return datetime(y, m, d).strftime("%Y-%m-%d")
        except ValueError:
            # Keep original if DMY parse fails.
            return v

    return v

def _extract_section_html_by_heading(soup: BeautifulSoup, heading_contains: str, max_chars: int = 15000) -> str:
    """
    Return HTML content after a heading containing text, until next heading.
    """
    heading = None
    target = heading_contains.lower()

    for tag in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
        t = tag.get_text(" ", strip=True)
        if t and target in t.lower():
            heading = tag
            break

    if not heading:
        return ""

    parts: List[str] = []
    total = 0
    for sib in heading.find_all_next():
        if sib.name in ["h1", "h2", "h3", "h4", "h5", "h6"]:
            break
        if sib.name in ["script", "style", "noscript"]:
            continue
        s = str(sib)
        parts.append(s)
        total += len(s)
        if total >= max_chars:
            break

    return " ".join(parts)


def extractor_cayman_csl_library_version(normalized_html: str) -> List[str]:
    """
    Cayman CSL:
    - Use the first CaymanSpectralLibrary_v... in "Version info" as latest.
    - Parse date-like versions as DMY(DDMMYYYY) -> YYYY-MM-DD.
    """
    soup = BeautifulSoup(normalized_html, "html.parser")

    # 1) Prefer "Version info" section HTML first
    sec_html = _extract_section_html_by_heading(soup, "Version info")
    if sec_html:
        blob = html_lib.unescape(sec_html)
    else:
        # If section lookup fails, fall back to full page content.
        blob = html_lib.unescape(normalized_html)

    # 2) First CaymanSpectralLibrary_v... is treated as latest.
    m = re.search(r"CaymanSpectralLibrary[_-]v?(\d{8}|\d+(?:\.\d+)+)", blob, flags=re.I)
    if m:
        raw_v = m.group(1).strip()
        fmt = _format_csl_version(raw_v)
        return [f"CSL Library version: {fmt} (v{raw_v})"]

    # 3) Final fallback: dateModified
    m2 = re.search(r'"dateModified"\s*:\s*"([^"]+)"', html_lib.unescape(normalized_html), flags=re.I)
    if m2:
        return [f"CSL dateModified: {m2.group(1).strip()}"]

    return []


def extractor_cayman_csl_fallback(normalized_html: str) -> List[str]:
    raw = html_lib.unescape(normalized_html)
    m = re.search(r'"dateModified"\s*:\s*"([^"]+)"', raw, flags=re.I)
    if m:
        return [f"CSL dateModified: {m.group(1).strip()}"]

    m2 = re.search(r"\bLast\s+updated\b[^<]{0,120}", raw, flags=re.I)
    if m2:
        return [clean_token(m2.group(0))]

    return []
    
def extractor_cayman_new_products_names(normalized_html: str) -> List[str]:
    """
    Cayman New Products에서 물질명/제품명을 추출.
    - /product/<id>/... 링크의 텍스트(없으면 aria-label/title)를 우선 사용
    - 텍스트가 비면 slug로 최소 이름 생성(item no보다 식별력 높음)
    """
    soup = BeautifulSoup(normalized_html, "html.parser")

    reject_words = {
        "add to cart", "learn more", "view", "search", "filter", "sort",
        "forensics", "products", "new products", "results", "item no",
    }

    entries: List[Tuple[int, str]] = []
    seen_pairs: Set[Tuple[int, str]] = set()

    for a in soup.find_all("a", href=True):
        href = a.get("href") or ""
        m_id = re.search(r"/product/(\d{4,8})/", href)
        if not m_id:
            continue

        txt = a.get_text(" ", strip=True) or a.get("aria-label") or a.get("title") or ""
        txt = clean_token(txt)

        if not txt:
            m = re.search(r"/product/\d{4,8}/([^?#/]+)", href)
            if m:
                txt = clean_token(m.group(1).replace("-", " "))

        low = txt.lower()
        if not txt or len(txt) < 4 or len(txt) > 90:
            continue
        if any(w in low for w in reject_words):
            continue
        if re.fullmatch(r"\d+", txt):
            continue
        if not re.search(r"[A-Za-z]", txt):
            continue

        product_id = int(m_id.group(1))
        pair = (product_id, txt)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        entries.append(pair)

    # Product id가 보통 최신 등록 순서를 반영하므로 내림차순 정렬 후 상단 토큰 생성.
    entries.sort(key=lambda x: x[0], reverse=True)

    uniq: List[str] = []
    seen: Set[str] = set()
    for _, n in entries:
        k = n.lower()
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)

    return uniq[:200]    
def extractor_cayman_itemno(normalized_html: str) -> List[str]:
    patterns = [r"\bItem\s*No\.?\s*[:#]?\s*(\d{4,8})\b"]
    return extract_by_regex_list(normalized_html, patterns, max_tokens=120)

def try_render_html_playwright(url: str) -> Tuple[str, str]:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (compatible; drug-news-briefing/1.0; +https://github.com/)",
                locale="ko-KR",
            )
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=60000)

            # Try networkidle when available; continue even if it times out.
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass

            html = page.content()
            browser.close()
        return html, ""
    except Exception as e:
        return "", f"Playwright failed: {type(e).__name__}: {e}"


def monitor_one(session: requests.Session, spec: MonitorSpec, prev_state: dict, timeout: int = 25) -> dict:
    now_kst = datetime.now(KST).isoformat(timespec="minutes")

    prev_entry = (prev_state or {}).get(spec.key, {}) if isinstance(prev_state, dict) else {}
    def normalize_hash_text(h: str) -> str:
        v = str(h or "").strip().lower()
        if v.startswith("sha256:"):
            v = v.split(":", 1)[1].strip()
        return v

    prev_hash = normalize_hash_text(prev_entry.get("hash", ""))
    prev_tokens_head = list(prev_entry.get("tokens_head", []) or [])[:12]

    def compute_changed(cur_hash: str) -> Optional[bool]:
        if not prev_hash:
            return None
        return normalize_hash_text(cur_hash) != prev_hash

    used_playwright = False
    html = ""
    req_err = ""

    # 1) Try requests first
    try:
        r = session.get(spec.url, timeout=timeout)
        if r.status_code == 200:
            html = r.text
        else:
            req_err = f"HTTP {r.status_code}"
    except Exception as e:
        req_err = f"requests failed: {type(e).__name__}: {e}"

    def extract_tokens_from_html(source_html: str) -> List[str]:
        normalized = normalize_html(
            source_html,
            soften_dates=spec.soften_dates,
            keep_jsonld=spec.keep_jsonld,
        )
        tokens = spec.extractor(normalized)
        if (not tokens) and spec.fallback_extractor:
            tokens = spec.fallback_extractor(normalized)
        return tokens

    tokens: List[str] = []
    if html:
        tokens = extract_tokens_from_html(html)

    # 2) Playwright fallback when needed
    pw_err = ""
    if (not tokens) and spec.use_playwright:
        rendered, pw_err = try_render_html_playwright(spec.url)
        if rendered:
            used_playwright = True
            tokens = extract_tokens_from_html(rendered)

    if not tokens:
        err = "Token extraction empty"
        if req_err:
            err = f"{req_err} / {err}"
        if spec.use_playwright and pw_err:
            err = f"{err} / {pw_err}"

        return {
            "key": spec.key,
            "name": spec.name,
            "url": spec.url,
            "ok": False,
            "changed": False,
            "error": err,
            "token_count": 0,
            "tokens_head": [],
            "prev_tokens_head": prev_tokens_head,  # show previous preview even on FAIL
            "hash": "",
            "prev_hash": prev_hash,
            "fetched_kst": now_kst,
            "used_playwright": used_playwright,
        }

    fp_text = "\n".join(tokens)
    cur_hash = sha256_hex(fp_text)

    note = "playwright fallback used" if used_playwright else ""
    return {
        "key": spec.key,
        "name": spec.name,
        "url": spec.url,
        "ok": True,
        "changed": compute_changed(cur_hash),
        "error": note,
        "token_count": len(tokens),
        "tokens_head": tokens[:12],
        "prev_tokens_head": prev_tokens_head,
        "hash": cur_hash,
        "prev_hash": prev_hash,
        "fetched_kst": now_kst,
        "used_playwright": used_playwright,
    }


def run_monitoring(session: requests.Session, prev_state: dict) -> Tuple[List[dict], dict, dict]:
    specs = [
        MonitorSpec(
            key="swgdrug_home",
            name="SWGDRUG Home",
            url="https://swgdrug.org/",
            extractor=extractor_swgdrug_additional_resources_3_5,
            soften_dates=False,
            use_playwright=False,
            keep_jsonld=False,
        ),
        MonitorSpec(
            key="cayman_csl",
            name="Cayman CSL Library",
            url="https://www.caymanchem.com/forensics/publications/csl",
            extractor=extractor_cayman_csl_library_version,
            fallback_extractor=extractor_cayman_csl_fallback,
            soften_dates=False,
            use_playwright=True,
            keep_jsonld=True,
        ),
        MonitorSpec(
            key="cayman_new_products",
            name="Cayman New Products",
            url="https://www.caymanchem.com/forensics/search/productSearch",
            extractor=extractor_cayman_new_products_names,
            fallback_extractor=extractor_cayman_itemno,
            soften_dates=True,
            use_playwright=True,
        ),
    ]

    results: List[dict] = []
    for spec in specs:
        results.append(monitor_one(session, spec, prev_state))
        time.sleep(1.0)

    updated = sum(1 for r in results if r.get("ok") and (r.get("changed") is True))
    failed = sum(1 for r in results if not r.get("ok"))

    summary = {
        "date_kst": datetime.now(KST).strftime("%Y-%m-%d"),
        "updated": updated,
        "failed": failed,
    }

    # Keep previous successful state when a site fails.
    new_state: dict = dict(prev_state) if isinstance(prev_state, dict) else {}

    for r in results:
        if r.get("ok") and r.get("hash"):
            new_state[r["key"]] = {
                "hash": r["hash"],
                "token_count": r.get("token_count", 0),
                "tokens_head": r.get("tokens_head", [])[:12],
                "fetched_kst": r.get("fetched_kst", ""),
                "url": r.get("url", ""),
                "name": r.get("name", ""),
            }

    meta = {
        "generated_kst": datetime.now(KST).isoformat(timespec="minutes"),
        "summary": summary,
    }

    return results, new_state, meta


def render_monitor_md(results: List[dict], summary: dict) -> str:
    lines: List[str] = []
    lines.append(f"# 감시 사이트 업데이트 요약 ({summary.get('date_kst','')})")
    lines.append("")
    lines.append(f"- 업데이트 감지: **{summary.get('updated',0)}**")
    lines.append(f"- 실패: **{summary.get('failed',0)}**")
    lines.append("")
    lines.append("## 결과")
    lines.append("")
    lines.append("| 사이트 | 상태 | 변경 | 토큰수 | 토큰 미리보기 | 비고 |")
    lines.append("|---|---:|---:|---:|---|---|")

    for r in results:
        name = f"[{r['name']}]({r['url']})"
        ok = "OK" if r.get("ok") else "FAIL"

        ch = r.get("changed")
        if ch is True:
            changed = "YES"
        elif ch is None:
            changed = "FIRST"
        else:
            changed = "NO"

        token_count = str(r.get("token_count", 0) or 0)

        toks = r.get("tokens_head", []) if r.get("ok") else (r.get("prev_tokens_head", []) or [])
        preview = " / ".join([shorten(str(t), 45) for t in toks[:3]]) if toks else ""
        note = r.get("error", "") or ""

        lines.append(f"| {name} | {ok} | {changed} | {token_count} | {escape_md(preview)} | {escape_md(note)} |")

    lines.append("")
    lines.append("## 변경 상세(상단 토큰)")
    lines.append("")
    for r in results:
        if r.get("ok") and (r.get("changed") is True):
            lines.append(f"### {r['name']}")
            lines.append(f"- URL: {r['url']}")
            lines.append(f"- 이전 해시: `{r.get('prev_hash','')}`")
            lines.append(f"- 현재 해시: `{r.get('hash','')}`")
            lines.append("")
            lines.append("상단 토큰(이전):")
            lines.append("")
            for t in (r.get("prev_tokens_head", []) or [])[:12]:
                lines.append(f"- {escape_md(shorten(str(t), 200))}")
            lines.append("")
            lines.append("상단 토큰(현재):")
            lines.append("")
            for t in r.get("tokens_head", [])[:12]:
                lines.append(f"- {escape_md(shorten(str(t), 200))}")
            lines.append("")

    return "\n".join(lines).strip() + "\n"


def render_monitor_html(results: List[dict], summary: dict) -> str:
    updated = int(summary.get("updated", 0) or 0)
    failed = int(summary.get("failed", 0) or 0)
    open_attr = " open" if (updated > 0 or failed > 0) else ""

    rows: List[str] = []
    for r in results:
        status = "OK" if r.get("ok") else "FAIL"
        ch = r.get("changed")
        if ch is True:
            changed = "YES"
        elif ch is None:
            changed = "FIRST"
        else:
            changed = "NO"

        cur_toks = r.get("tokens_head", []) if r.get("ok") else (r.get("prev_tokens_head", []) or [])
        cur_preview = "<br>".join([escape_html(shorten(str(t), 55)) for t in cur_toks[:3]]) if cur_toks else ""

        preview_html = f"<code>{cur_preview}</code>"

        if r.get("ok") and (r.get("changed") is True):
            prev_toks = r.get("prev_tokens_head", []) or []
            prev_preview = "<br>".join([escape_html(shorten(str(t), 55)) for t in prev_toks[:3]]) if prev_toks else ""
            if prev_preview:
                preview_html = (
                    f"<div><span class='meta'>현재</span><br><code>{cur_preview}</code></div>"
                    f"<div style='margin-top:6px'><span class='meta'>이전</span><br><code>{prev_preview}</code></div>"
                )

        note = r.get("error", "") or ""

        rows.append(
            "<tr>"
            f"<td><a href='{escape_attr(r['url'])}' target='_blank' rel='noopener noreferrer'>{escape_html(r['name'])}</a></td>"
            f"<td>{escape_html(status)}</td>"
            f"<td>{escape_html(changed)}</td>"
            f"<td style='text-align:right'>{int(r.get('token_count',0) or 0)}</td>"
            f"<td>{preview_html}</td>"
            f"<td>{escape_html(note)}</td>"
            "</tr>"
        )

    kpi = (
        "<div class='kpi'>"
        f"<span class='badge'>감시 업데이트 {updated}</span>"
        f"<span class='badge'>감시 실패 {failed}</span>"
        "</div>"
    )

    return (
        f"{kpi}"
        f"<details{open_attr}>"
        f"<summary>감시 사이트 결과 (업데이트 {updated} / 실패 {failed})</summary>"
        "<div class='box'>"
        "<table class='table'>"
        "<thead><tr><th>사이트</th><th>상태</th><th>변경</th><th style='text-align:right'>토큰수</th><th>토큰 미리보기</th><th>비고</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
        "</div>"
        "</details>"
    )


# =========================
# HTML Utilities
# =========================
def escape_html(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def escape_attr(s: str) -> str:
    return escape_html(s)


def escape_md(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()


def build_page_html(news_html: str, monitor_html: str, meta: dict) -> str:
    generated_kst = meta.get("generated_kst", "")

    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <meta name="color-scheme" content="light dark"/>
  <title>마약 뉴스 브리핑 + 감시 요약</title>
  <link rel="stylesheet" href="./style.css">
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>마약 뉴스 브리핑 + 감시 요약</h1>
        <div class="subline">생성 시각(KST): {escape_html(generated_kst)}</div>
      </div>
    </div>

    <div class="section">
      <div class="section-head">
        <h2>뉴스 브리핑(최근 24시간)</h2>
      </div>
      {news_html}
    </div>

    <div class="section">
      <div class="section-head">
        <h2>감시 사이트 업데이트 요약</h2>
      </div>
      {monitor_html}
    </div>
  </div>
</body>
</html>
"""


# =========================
# Main
# =========================
def main() -> None:
    ensure_docs_dir()
    session = build_session()

    # 1) 뉴스 브리핑
    clusters, news_stats = collect_news_last_24h(session)
    news_html = render_news_html(clusters, news_stats)

    # 2) 감시 결과 수집(이전 state 로드 후 비교)
    prev_state = load_prev_state(session)
    results, new_state, meta = run_monitoring(session, prev_state)

    summary = meta.get("summary", {})
    monitor_html = render_monitor_html(results, summary)

    # 3) 출력물 저장
    write_json(STATE_JSON, {"meta": meta, "sites": new_state})

    md = render_monitor_md(results, summary)
    with open(MONITOR_MD, "w", encoding="utf-8") as f:
        f.write(md)

    write_json(MONITOR_SUMMARY_JSON, summary)

    page_html = build_page_html(news_html, monitor_html, meta)
    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(page_html)

    print("[OK] Generated:")
    print(" -", INDEX_HTML)
    print(" -", STATE_JSON)
    print(" -", MONITOR_MD)
    print(" -", MONITOR_SUMMARY_JSON)


if __name__ == "__main__":
    main()


