#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import hashlib
import difflib
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
    THRESH_WITH_ANCHOR = 0.52   # anchor/숫자 겹침 있을 때는 공격적으로
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
    변경점:
    - 사건 단위로만 노출(대표 기사 1개)
    - 같은 사건으로 묶인 기사 1건(+1)은 "리스트로는" 보여주지 않음
    - +2 이상일 때만 details로 추가 기사 리스트 노출
    """
    if not event_clusters:
        return "<p>최근 24시간 기준 수집된 뉴스가 없습니다.</p>"

    collected = int(stats.get("collected", 0) or 0)
    events = int(stats.get("events", 0) or 0)

    blocks: List[str] = []
    for idx, c in enumerate(event_clusters, start=1):
        rep = c["rep"]
        others = c.get("others", [])
        extra_n = len(others)

        pub = f"<span class='meta'>[{escape_html(rep.get('publisher',''))}]</span> " if rep.get("publisher") else ""
        ts = f"<span class='meta'>{escape_html(rep.get('published_kst',''))}</span>"

        badge_extra = f" <span class='badge small'>+{extra_n}건</span>" if extra_n else ""

        head = (
            f"<div class='event-head'>"
            f"<span class='event-no'>[사건 {idx}]</span> "
            f"{pub}<a href='{escape_attr(rep.get('link',''))}' target='_blank' rel='noopener noreferrer'>"
            f"{escape_html(rep.get('title',''))}</a> {ts}"
            f"{badge_extra}"
            f"</div>"
        )

        tail = ""
        if extra_n >= 2:
            lis = []
            others_sorted = sorted(others, key=lambda x: x.get("published_ts", 0), reverse=True)
            for o in others_sorted[:25]:
                opub = f"<span class='meta'>[{escape_html(o.get('publisher',''))}]</span> " if o.get("publisher") else ""
                ots = f"<span class='meta'>{escape_html(o.get('published_kst',''))}</span>"
                lis.append(
                    f"<li>{opub}<a href='{escape_attr(o.get('link',''))}' target='_blank' rel='noopener noreferrer'>"
                    f"{escape_html(o.get('title',''))}</a> {ots}</li>"
                )
            tail = (
                "<details class='event-more'>"
                f"<summary>같은 사건으로 묶인 기사 {extra_n}건 보기</summary>"
                f"<ul>{''.join(lis)}</ul>"
                "</details>"
            )

        blocks.append(f"<div class='event'>{head}{tail}</div>")

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


def normalize_html(html: str, soften_dates: bool = True) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
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


def extractor_swgdrug(normalized_html: str) -> List[str]:
    patterns = [
        r"SWGDRUG\s*(?:Recommendations|Recommendations\s+and\s+Reports|Documents)?",
        r"(Recommendations\s+and\s+Reports)",
        r"(Minutes)",
        r"(Monographs)",
        r"(Technical\s+notes?)",
        r"href=['\"]([^'\"]+\.pdf)['\"]",
        r"href=['\"]([^'\"]+\.docx?)['\"]",
        r"href=['\"]([^'\"]+\.xlsx?)['\"]",
        r"\b(Version\s*\d+(?:\.\d+)*)\b",
        r"\b(Revision\s*\d+(?:\.\d+)*)\b",
    ]
    tokens = extract_by_regex_list(normalized_html, patterns, max_tokens=140)
    cleaned = []
    for t in tokens:
        if t.lower().endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx")):
            cleaned.append(re.sub(r".*/", "", t))
        else:
            cleaned.append(t)
    return cleaned


def extractor_cayman_csl_version_additions(normalized_html: str) -> List[str]:
    soup = BeautifulSoup(normalized_html, "html.parser")

    def collect_section_text(title: str) -> str:
        heading = None
        for tag in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
            t = tag.get_text(" ", strip=True)
            if t and title.lower() in t.lower():
                heading = tag
                break

        if heading:
            texts = []
            for sib in heading.find_all_next():
                if sib.name in ["h1", "h2", "h3", "h4", "h5", "h6"]:
                    break
                if sib.name in ["script", "style", "noscript"]:
                    continue
                txt = sib.get_text(" ", strip=True) if hasattr(sib, "get_text") else ""
                if txt:
                    texts.append(txt)
                if len(" ".join(texts)) > 2000:
                    break
            return " ".join(texts).strip()

        m = re.search(rf"({re.escape(title)}.{0,1500})", normalized_html, flags=re.I)
        if m:
            chunk = re.sub(r"<[^>]+>", " ", m.group(1))
            chunk = re.sub(r"\s+", " ", chunk).strip()
            return chunk

        return ""

    vi = collect_section_text("Version info")
    ad = collect_section_text("Additions")

    tokens = []
    if vi:
        tokens.append("Version info:" + vi)
    if ad:
        tokens.append("Additions:" + ad)

    return [t[:2000] for t in tokens]


def extractor_cayman_csl_fallback(normalized_html: str) -> List[str]:
    """
    CSL이 JS 렌더링/레이아웃 변경으로 heading 탐지가 실패할 때 대비.
    """
    patterns = [
        r'"dateModified"\s*:\s*"([^"]+)"',
        r'"datePublished"\s*:\s*"([^"]+)"',
        r'"lastModified"\s*:\s*"([^"]+)"',
        r"\bLast\s+updated\b[^<]{0,120}",
        r"\bUpdated\b[^<]{0,120}",
        r"(Version\s*info.{0,600})",
        r"(Additions.{0,900})",
    ]
    raw = extract_by_regex_list(normalized_html, patterns, max_tokens=20)
    cleaned = []
    for t in raw:
        t2 = re.sub(r"<[^>]+>", " ", t)
        t2 = re.sub(r"\s+", " ", t2).strip()
        if t2:
            cleaned.append(t2)
    return cleaned[:8]


def extractor_cayman_itemno(normalized_html: str) -> List[str]:
    patterns = [r"\bItem\s*No\.?\s*[:#]?\s*(\d{4,8})\b"]
    return extract_by_regex_list(normalized_html, patterns, max_tokens=120)


def extractor_cayman_fallback(normalized_html: str) -> List[str]:
    patterns = [
        r"property=['\"]og:updated_time['\"][^>]*content=['\"]([^'\"]+)['\"]",
        r"\bLast\s+updated\b[^<]{0,120}",
        r"\bUpdated\b[^<]{0,120}",
    ]
    return extract_by_regex_list(normalized_html, patterns, max_tokens=60)


def try_render_html_playwright(url: str) -> Tuple[str, str]:
    """
    Playwright 렌더링으로 HTML 획득.
    - 성공: (html, "")
    - 실패: ("", "error")
    """
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=60000)
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
        normalized = normalize_html(source_html, soften_dates=spec.soften_dates)
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
            extractor=extractor_swgdrug,
            soften_dates=True,
            use_playwright=False,
        ),
        MonitorSpec(
            key="cayman_csl",
            name="Cayman CSL Library",
            url="https://www.caymanchem.com/forensics/publications/csl",
            extractor=extractor_cayman_csl_version_additions,
            fallback_extractor=extractor_cayman_csl_fallback,
            soften_dates=False,
            use_playwright=True,  # ✅ requests로 토큰이 비면 playwright 렌더링 시도
        ),
        MonitorSpec(
            key="cayman_new_products",
            name="Cayman New Products",
            url="https://www.caymanchem.com/forensics/search/productSearch",
            extractor=extractor_cayman_itemno,
            fallback_extractor=extractor_cayman_fallback,
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

    new_state: dict = {}
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
        preview = "<br>".join([escape_html(shorten(str(t), 55)) for t in toks[:3]]) if toks else ""
        note = r.get("error", "") or ""

        rows.append(
            "<tr>"
            f"<td><a href='{escape_attr(r['url'])}' target='_blank' rel='noopener noreferrer'>{escape_html(r['name'])}</a></td>"
            f"<td>{escape_html(status)}</td>"
            f"<td>{escape_html(changed)}</td>"
            f"<td style='text-align:right'>{int(r.get('token_count',0) or 0)}</td>"
            f"<td><code>{preview}</code></td>"
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
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>마약류 뉴스 브리핑 + 감시 점검</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; line-height: 1.55; margin: 24px; }}
    h1 {{ margin: 0 0 6px 0; font-size: 22px; }}
    h2 {{ margin-top: 22px; font-size: 18px; }}
    .meta {{ color: #666; font-size: 12px; margin-left: 6px; }}
    .badge {{ display:inline-block; padding:4px 10px; border:1px solid #ddd; border-radius:999px; margin:0 6px 6px 0; font-size:13px; }}
    .badge.small {{ font-size: 12px; padding: 2px 8px; }}
    .kpi {{ margin: 10px 0 8px 0; }}
    a {{ color: inherit; }}
    ul {{ padding-left: 18px; }}
    li {{ margin: 6px 0; }}
    details {{ margin-top: 12px; }}
    summary {{ cursor: pointer; font-weight: 700; }}
    .box {{ margin-top: 10px; padding: 10px; border: 1px solid #eee; border-radius: 10px; }}
    .table {{ width: 100%; border-collapse: collapse; }}
    .table th, .table td {{ border-bottom: 1px solid #eee; padding: 8px; font-size: 13px; vertical-align: top; }}
    .footer {{ margin-top: 18px; color: #777; font-size: 12px; }}

    .event {{ border: 1px solid #eee; border-radius: 12px; padding: 10px 12px; margin: 10px 0; }}
    .event-head {{ font-size: 14px; }}
    .event-no {{ font-weight: 800; margin-right: 6px; }}
    .event-more summary {{ font-weight: 600; font-size: 13px; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>마약류 뉴스 브리핑 + 감시 점검</h1>
  <div class="footer">생성 시각(KST): {escape_html(generated_kst)}</div>

  <h2>뉴스 브리핑 (최근 24시간)</h2>
  {news_html}

  <h2>감시 사이트 업데이트 점검</h2>
  {monitor_html}

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
