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

import pytz
import feedparser
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# =========================
# Time / Globals
# =========================
KST = pytz.timezone("Asia/Seoul")

DOCS_DIR = "docs"
INDEX_HTML = os.path.join(DOCS_DIR, "index.html")
STATE_JSON = os.path.join(DOCS_DIR, "site_state.json")
MONITOR_MD = os.path.join(DOCS_DIR, "site_monitor.md")
MONITOR_SUMMARY_JSON = os.path.join(DOCS_DIR, "monitor_summary.json")

SITE_STATE_URL = os.getenv("SITE_STATE_URL", "").strip()  # raw gh-pages json (optional)


# =========================
# HTTP Session (retry/backoff)
# =========================
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
    return s


# =========================
# Helpers
# =========================
def ensure_docs_dir() -> None:
    os.makedirs(DOCS_DIR, exist_ok=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_get_json(session: requests.Session, url: str, timeout: int = 20) -> Optional[dict]:
    """session 기반 (retry/backoff 적용)"""
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
    우선순위:
      1) SITE_STATE_URL(gh-pages raw)에서 전날 상태 로드 시도
      2) 로컬 docs/site_state.json
      3) 없으면 빈 dict

    저장 구조가 {"meta":..., "sites":{...}} 이므로 항상 sites를 반환하도록 보정.
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
    return s[: max_len - 1] + "…"

def clean_token(s: str) -> str:
    """
    토큰에 섞이는 HTML 엔티티/태그/공백을 정리해서 사람이 읽기 쉽게 만든다.
    """
    s = html_lib.unescape(s or "")
    s = re.sub(r"<[^>]+>", " ", s)      # <br> 같은 태그 제거
    s = re.sub(r"\s+", " ", s).strip()
    return s
    
# =========================
# News Briefing (A안: 의존성 없음, 범용 중복 제거 강화)
# =========================
def build_google_news_rss_url(query: str, hl: str = "ko", gl: str = "KR", ceid: str = "KR:ko") -> str:
    from urllib.parse import quote_plus

    return "https://news.google.com/rss/search?q=" + quote_plus(query) + f"&hl={hl}&gl={gl}&ceid={ceid}"


def normalize_title(title: str) -> str:
    t = title.strip()
    # 흔한 꼬리표 정리: " - 언론사"
    t = re.sub(r"\s+-\s+[^-]{2,40}$", "", t).strip()
    # 괄호류 단순 정리
    t = re.sub(r"[\[\]【】()（）]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def extract_publisher(raw_title: str) -> str:
    m = re.search(r"\s+-\s+([^-]{2,40})$", raw_title.strip())
    return m.group(1).strip() if m else ""


NEWS_STYLE_NOISE = [
    "단독", "속보", "전격", "충격", "파문", "논란", "비판",
    "초비상", "위기", "날벼락", "대참사", "경악", "난리",
    "전망", "무산", "급증", "급락", "폭등", "폭락",
    "결국", "드디어",
]
COMMON_FILLERS = [
    "했다", "한다", "관련", "이유", "사실상", "추정",
    "가능성", "전면", "공식", "최근", "오늘", "어제", "내일",
]


def normalize_title_strong(raw_title: str) -> str:
    """범용 중복 제거용: 표현 차이를 크게 줄여 사건 단위 비교에 유리하게 만든다."""
    t = normalize_title(raw_title)

    # 인용/강조 기호 제거
    t = re.sub(r"[“”‘’'\"…·•※◆■★☆▶️]", " ", t)
    t = re.sub(r"[|/]", " ", t)
    t = re.sub(r"[:;]", " ", t)

    # 서수/표현 통일
    t = re.sub(r"\b두\s*번째\b", "2번째", t)
    t = re.sub(r"\b세\s*번째\b", "3번째", t)
    t = re.sub(r"\b네\s*번째\b", "4번째", t)
    t = re.sub(r"\b(\d+)\s*번째\b", r"\1번째", t)

    # 뉴스 문체 노이즈 제거
    for p in NEWS_STYLE_NOISE:
        t = re.sub(rf"\b{re.escape(p)}\b", " ", t, flags=re.I)
    for p in COMMON_FILLERS:
        t = re.sub(rf"\b{re.escape(p)}\b", " ", t, flags=re.I)

    t = re.sub(r"\s+", " ", t).strip()
    return t


GENERIC_STOPWORDS = set(
    [
        "또", "다시", "이후", "관련", "이유", "사실", "사실상", "추정", "가능성",
        "오늘", "어제", "내일", "이번", "지난", "최근", "현재", "당시",
        "논란", "파문", "충격", "전격", "속보", "단독", "전망", "무산",
        "공식", "전면", "급증", "급락", "결국", "드디어",
    ]
)
KOREAN_PARTICLES = ("은", "는", "이", "가", "을", "를", "에", "에서", "으로", "와", "과", "도", "만")


def strip_korean_particle(token: str) -> str:
    """
    형태소 분석 없이 '사건 비교' 목적의 아주 약한 보정:
    - 3글자 이상 한글 토큰이면 끝 조사 일부 제거
    """
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

    # 중복 제거(순서 유지)
    seen: Set[str] = set()
    uniq: List[str] = []
    for t in out:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
    return uniq


def anchor_tokens(tokens: List[str]) -> Set[str]:
    """
    anchor = 사건을 구분하는 데 도움이 되는 토큰(고유명사/숫자/긴 단어 등)
    """
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
    0~1 범용 사건 유사도:
    - core jaccard
    - anchor jaccard(더 중요)
    - token-sorted 문자열의 SequenceMatcher 비율(어순 변화에 강함)
    - 숫자 교집합 보너스
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
    강화된 범용 사건 클러스터링:
    - exact(강정규화 해시) 1차 제거
    - anchor 기반 후보군 탐색 + 결합 유사도 점수
    - 2차(클러스터 대표끼리) merge pass로 split cluster 추가 병합
    """
    # ---- 1) exact dedup(강정규화 해시) ----
    by_hash: Dict[str, dict] = {}
    for it in items:
        f = make_features(it)
        h = f["hash"]
        if h not in by_hash:
            by_hash[h] = it
        else:
            # 대표 선정: 최신(업데이트 반영)
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

    # ✅ 튜닝 포인트 (중복이 많으면 WITH_ANCHOR를 0.50~0.52 쪽으로 낮춰보는 게 효과 큼)
    THRESH_WITH_ANCHOR = 0.50   # anchor/숫자 겹침 있을 때는 공격적으로
    THRESH_NO_ANCHOR = 0.70     # anchor/숫자 겹침 없으면 매우 비슷할 때만 병합

    for it in dedup_stage1:
        fi = make_features(it)

        cand: Set[int] = set()
        for t in list(fi["anchors"])[:8]:
            cand |= inv.get(t, set())
        for n in list(fi["nums"])[:4]:
            cand |= inv.get(n, set())

        if not cand:
            # 후보가 없으면 최근 클러스터 일부만 비교(시간 지역성)
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

    # ---- 3) merge pass(대표끼리 한 번 더 병합) ----
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

    query = "(마약 OR 마약류 OR 향정 OR 약물) AND (적발 OR 검거 OR 압수 OR 밀수 OR 수사 OR 단속 OR 운전)"
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
    - 사건 단위로 대표 기사만 노출
    - 추가기사 목록(details)은 아예 노출하지 않음
    - 필요하면 +N건 배지는 유지(원치 않으면 badge_extra 줄을 빈 문자열로 바꾸면 됨)
    """
    if not event_clusters:
        return "<p>최근 24시간 기준 수집된 뉴스가 없습니다.</p>"

    collected = int(stats.get("collected", 0) or 0)
    events = int(stats.get("events", 0) or 0)

    blocks: List[str] = []
    for idx, c in enumerate(event_clusters, start=1):
        rep = c["rep"]
        extra_n = len(c.get("others", []) or [])

        pub = f"<span class='meta'>[{escape_html(rep.get('publisher',''))}]</span> " if rep.get("publisher") else ""
        ts = f"<span class='meta'>{escape_html(rep.get('published_kst',''))}</span>"

        # ✅ +N건 표시만 유지 (완전히 숨기려면 아래 줄을 badge_extra = "" 로 변경)
        badge_extra = f" <span class='badge small'>+{extra_n}건</span>" if extra_n else ""

        head = (
            f"<div class='event'>"
            f"<div class='event-head'>"
            f"<span class='event-no'>[사건 {idx}]</span> "
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
        f"<span class='badge'>사건 {events}개</span>"
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
    use_playwright: bool = False  # requests로 안 되면 playwright 렌더링 fallback
    keep_jsonld: bool = False     # ✅ CSL 같은 페이지에서 JSON-LD(script) 유지 옵션


def normalize_html(html: str, soften_dates: bool = True, keep_jsonld: bool = False) -> str:
    soup = BeautifulSoup(html, "html.parser")

    # style/noscript 제거
    for tag in soup(["style", "noscript"]):
        tag.decompose()

    # script 처리:
    # - 기본: 전부 제거
    # - keep_jsonld=True면 application/ld+json만 남기고 나머지 제거
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
    SWGDRUG 홈 'Additional Resources'의
    3) SWGDRUG Recommendations Version ...
    5) Searchable Mass Spectral Library Version ...
    두 줄만 토큰으로 반환 (사람이 보기 쉬운 형태)
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

    # fallback: 문장 매칭 실패 시 버전만이라도
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
    CSL 버전이 8자리 숫자일 때 DMY(DDMMYYYY)로 해석해 YYYY-MM-DD로 반환.
    - DMY가 유효하지 않으면(예: 05162013 -> 월=16) None
    - (안전망) YYYYMMDD 형태로만 유효하면 그걸로 반환
    - MMDDYYYY는 의도적으로 해석하지 않음(과거 파일명이 섞일 때 오탐 방지)
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

    # 2) (안전망) YYYYMMDD만 유효하면 그쪽으로
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
    8자리면 DMY(DDMMYYYY)로만 해석해 YYYY-MM-DD 반환.
    (MMDDYYYY는 의도적으로 해석하지 않음: 과거 파일명 오탐 방지)
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
            # DMY로 성립 안 하면 원문 유지
            return v

    return v

def _extract_section_html_by_heading(soup: BeautifulSoup, heading_contains: str, max_chars: int = 15000) -> str:
    """
    heading_contains(예: 'Version info')를 포함하는 heading 이후,
    다음 heading 전까지의 'HTML 문자열'을 반환 (href 등 속성 포함).
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
    - Version info 섹션은 최신이 가장 위 → 그 섹션에서 첫 번째 CaymanSpectralLibrary_v...만 사용
    - 날짜는 DMY(DDMMYYYY)로 YYYY-MM-DD 표출
    """
    soup = BeautifulSoup(normalized_html, "html.parser")

    # 1) Version info 섹션 HTML(링크 href 포함) 우선
    sec_html = _extract_section_html_by_heading(soup, "Version info")
    if sec_html:
        blob = html_lib.unescape(sec_html)
    else:
        # heading 탐지 실패 시 전체 HTML로 차선
        blob = html_lib.unescape(normalized_html)

    # 2) 섹션 내 '첫 번째' CaymanSpectralLibrary_v... 가 최신(페이지 설계 가정)
    m = re.search(r"CaymanSpectralLibrary[_-]v?(\d{8}|\d+(?:\.\d+)+)", blob, flags=re.I)
    if m:
        raw_v = m.group(1).strip()
        fmt = _format_csl_version(raw_v)
        # 원문도 남기고 싶으면 (v{raw_v}) 유지, 싫으면 제거
        return [f"CSL Library version: {fmt} (v{raw_v})"]

    # 3) 최후 fallback: dateModified만
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
    - /product/<id>/... 링크의 텍스트(또는 aria-label/title)를 최우선 사용
    - 텍스트가 비면 slug로 최소 이름 생성(그래도 itemno보다는 낫게)
    """
    soup = BeautifulSoup(normalized_html, "html.parser")

    reject_words = {
        "add to cart", "learn more", "view", "search", "filter", "sort",
        "forensics", "products", "new products", "results", "item no",
    }

    names: List[str] = []
    for a in soup.find_all("a", href=True):
        href = a.get("href") or ""
        if not re.search(r"/product/\d{4,8}/", href):
            continue

        txt = a.get_text(" ", strip=True) or a.get("aria-label") or a.get("title") or ""
        txt = clean_token(txt)

        if not txt:
            # 텍스트가 없으면 slug로 최소 이름 생성
            m = re.search(r"/product/\d{4,8}/([^?#/]+)", href)
            if m:
                txt = clean_token(m.group(1).replace("-", " "))

        low = txt.lower()
        if not txt or len(txt) < 4 or len(txt) > 90:
            continue
        if any(w in low for w in reject_words):
            continue
        # 숫자만이면 제외
        if re.fullmatch(r"\d+", txt):
            continue
        # 알파벳이 전혀 없으면(거의 UI 텍스트 가능성) 제외
        if not re.search(r"[A-Za-z]", txt):
            continue

        names.append(txt)

    # 중복 제거(대소문자 무시)
    uniq: List[str] = []
    seen: Set[str] = set()
    for n in names:
        k = n.lower()
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)

    # 순서 흔들림(정렬/리렌더)로 인한 불필요 변경을 줄이려면 정렬 추천
    uniq = sorted(uniq, key=lambda s: s.lower())

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

            # networkidle은 "되면 좋고, 안 되면 넘어가자" 수준으로만
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
    prev_hash = str(prev_entry.get("hash", "") or "")
    prev_tokens_head = list(prev_entry.get("tokens_head", []) or [])[:12]

    def compute_changed(cur_hash: str) -> Optional[bool]:
        if not prev_hash:
            return None
        return cur_hash != prev_hash

    used_playwright = False
    html = ""
    req_err = ""

    # 1) requests 시도
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

    # 2) 필요 시 playwright fallback
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
            "prev_tokens_head": prev_tokens_head,  # ✅ FAIL이어도 전날 토큰 미리보기 제공
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
            name="SWGDRUG 홈",
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
            extractor=extractor_cayman_new_products_names,   # ✅ 물질명
            fallback_extractor=extractor_cayman_itemno,       # 최후 보험
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

    # ✅ FAIL이 나도 이전 성공 state를 유지(토큰 미리보기/비교 안정화)
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
    lines.append(f"# 감시 사이트 업데이트 점검 ({summary.get('date_kst','')})")
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

        toks = r.get("tokens_head", []) if r.get("ok") else (r.get("prev_tokens_head", []) or [])
        cur_toks = r.get("tokens_head", []) if r.get("ok") else (r.get("prev_tokens_head", []) or [])
        cur_preview = "<br>".join([escape_html(shorten(str(t), 55)) for t in cur_toks[:3]]) if cur_toks else ""

        preview_html = f"<code>{cur_preview}</code>"

        # ✅ 변경(YES)인 경우: 이전 토큰도 같이 보여주기
        if r.get("ok") and (r.get("changed") is True):
            prev_toks = r.get("prev_tokens_head", []) or []
            prev_preview = "<br>".join([escape_html(shorten(str(t), 55)) for t in prev_toks[:3]]) if prev_toks else ""
            if prev_preview:
                preview_html = (
                    f"<div><span class='meta'>현재</span><br><code>{cur_preview}</code></div>"
                    f"<div style='margin-top:6px'><span class='meta'>이전</span><br><code>{prev_preview}</code></div>"
                )

        # 그리고 rows.append에서 <td><code>...</code></td> 대신 preview_html을 그대로 넣기
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
        f"<summary>감시 사이트 점검 결과 (업데이트 {updated} · 실패 {failed})</summary>"
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
  <link rel="stylesheet" href="./style.css">
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>마약류 뉴스 브리핑 + 감시 점검</title> 
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>마약류 뉴스 브리핑 + 감시 점검</h1>
        <div class="subline">생성 시각(KST): ...</div>
      </div>
    </div>

    <div class="section">
      <div class="section-head">
        <h2>뉴스 브리핑 (최근 24시간)</h2>
      </div>
      <!-- kpi + events -->
      {{news_html}}
    </div>

    <div class="section">
      <div class="section-head">
        <h2>감시 사이트 업데이트 점검</h2>
      </div>
      {{monitor_html}}
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

    # 2) 감시(전날 state 로드 → 비교)
    prev_state = load_prev_state(session)
    results, new_state, meta = run_monitoring(session, prev_state)

    summary = meta.get("summary", {})
    monitor_html = render_monitor_html(results, summary)

    # 3) 산출물 저장
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
