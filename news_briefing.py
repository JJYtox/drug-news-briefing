#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

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
    """
    ✅ session 기반 (retry/backoff 적용)
    """
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

    주의:
      저장 구조가 {"meta":..., "sites":{...}} 이므로,
      항상 sites를 반환하도록 보정한다.
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


# =========================
# News Briefing (A안: 의존성 없음, 범용 중복 제거)
# =========================
def build_google_news_rss_url(query: str, hl: str = "ko", gl: str = "KR", ceid: str = "KR:ko") -> str:
    # Google News RSS
    # 예: https://news.google.com/rss/search?q=...&hl=ko&gl=KR&ceid=KR:ko
    from urllib.parse import quote_plus

    return (
        "https://news.google.com/rss/search?q="
        + quote_plus(query)
        + f"&hl={hl}&gl={gl}&ceid={ceid}"
    )


def normalize_title(title: str) -> str:
    t = title.strip()
    # 흔한 꼬리표 정리: " - 언론사"
    t = re.sub(r"\s+-\s+[^-]{2,40}$", "", t).strip()
    # 괄호류 단순 정리
    t = re.sub(r"[\[\]【】()（）]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def extract_publisher(raw_title: str) -> str:
    # "제목 - 언론사" 형태에서 언론사 추출
    m = re.search(r"\s+-\s+([^-]{2,40})$", raw_title.strip())
    return m.group(1).strip() if m else ""


# --- 범용 강한 정규화(도메인 의존 X) ---
NEWS_STYLE_NOISE = [
    "단독",
    "속보",
    "전격",
    "충격",
    "파문",
    "논란",
    "비판",
    "초비상",
    "위기",
    "날벼락",
    "큰일",
    "큰일났다",
    "대참사",
    "경악",
    "화들짝",
    "난리",
    "전망",
    "무산",
    "급증",
    "급락",
    "폭등",
    "폭락",
    "해체하나",
    "시즌아웃",
    "시즌 아웃",
    "결국",
    "드디어",
    "또",
    "다시",
]

COMMON_FILLERS = [
    "했다",
    "한다",
    "했다가",
    "한다는",
    "한다며",
    "관련",
    "이유",
    "사실상",
    "추정",
    "가능성",
    "전면",
    "공식",
    "최근",
    "오늘",
    "어제",
    "내일",
]

def normalize_title_strong(raw_title: str) -> str:
    """
    ✅ 범용 중복 제거용: 표현 차이를 크게 줄여 "사건 단위" 비교에 유리하게 만든다.
    - 언론사 꼬리표 제거/괄호 정리(기존 normalize_title)
    - 인용부호/특수기호/이모지 제거 강화
    - 뉴스 문체 수식어/군더더기(도메인 비의존) 제거
    - 숫자/단위는 유지(사건 식별에 도움)
    """
    t = normalize_title(raw_title)

    # 인용/강조 기호 제거
    t = re.sub(r"[“”‘’'\"…·•▶️★☆※◆■◆▶️]", " ", t)

    # 연속 구분자/기호 정리
    t = re.sub(r"[|/]", " ", t)
    t = re.sub(r"[:;]", " ", t)

    # 흔한 서수/숫자 표현 통일(범용)
    t = re.sub(r"\b두\s*번째\b", "2번째", t)
    t = re.sub(r"\b세\s*번째\b", "3번째", t)
    t = re.sub(r"\b네\s*번째\b", "4번째", t)
    t = re.sub(r"\b(\d+)\s*번째\b", r"\1번째", t)

    # 노이즈 제거(단어 경계 고려)
    for p in NEWS_STYLE_NOISE:
        t = re.sub(rf"\b{re.escape(p)}\b", " ", t, flags=re.I)
    for p in COMMON_FILLERS:
        t = re.sub(rf"\b{re.escape(p)}\b", " ", t, flags=re.I)

    # 불필요 공백
    t = re.sub(r"\s+", " ", t).strip()
    return t


# --- 범용 핵심 토큰 기반 비교 ---
GENERIC_STOPWORDS = set([
    # 매우 흔한 기능어/일반어 (도메인 비의존)
    "또", "다시", "이후", "관련", "이유", "사실", "사실상", "추정", "가능성",
    "오늘", "어제", "내일", "이번", "지난", "최근", "현재", "당시",
    "논란", "파문", "충격", "전격", "속보", "단독", "전망", "무산",
    "공식", "전면", "급증", "급락", "결국", "드디어",
    # 조사/어미 유사 토큰이 섞일 때 대비(완전 형태소 분석 없이 최소)
    "에서", "으로", "에게", "하고", "하며", "했다", "한다",
])

def core_tokens(raw_title: str) -> List[str]:
    """
    - 강한 정규화 후
    - 한/영/숫자 토큰 추출
    - 너무 일반적인 토큰 제거 + 너무 짧은 토큰 제거
    """
    s = normalize_title_strong(raw_title).lower()
    toks = re.findall(r"[0-9A-Za-z가-힣]+", s)

    out: List[str] = []
    for t in toks:
        if len(t) <= 1:
            continue
        if t in GENERIC_STOPWORDS:
            continue
        out.append(t)

    # 중복 제거(순서 유지)
    seen = set()
    uniq = []
    for t in out:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
    return uniq


def jaccard_set(a: List[str], b: List[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def score_event_similarity(raw_a: str, raw_b: str) -> float:
    """
    ✅ 범용 사건 유사도 점수(0~1):
    - core token jaccard를 기본으로 하고,
    - 숫자 토큰(예: 162, 2, 2026 등) 일치가 있으면 보너스
    """
    ta = core_tokens(raw_a)
    tb = core_tokens(raw_b)
    base = jaccard_set(ta, tb)

    # 숫자 토큰 보너스: 숫자가 겹치면 같은 사건일 확률↑
    na = set(re.findall(r"\b\d+\b", normalize_title_strong(raw_a)))
    nb = set(re.findall(r"\b\d+\b", normalize_title_strong(raw_b)))
    if na and nb:
        num_j = len(na & nb) / len(na | nb)
        base = min(1.0, base + 0.12 * num_j)

    return base


def cluster_news_events(items: List[dict]) -> List[dict]:
    """
    ✅ 아이템들을 '사건(event) 클러스터'로 묶는다.
    반환: [
      {
        "rep": 대표기사(dict),
        "others": [추가기사들...],
        "count": int,
        "cluster_key": str,
      }, ...
    ]
    """
    clusters: List[dict] = []

    # 대표 선정 정책(범용):
    # - 클러스터 내에서 "가장 최신"을 대표로(업데이트 반영)
    #   필요하면 "가장 이른"으로 바꾸려면 아래 choose_rep만 변경
    def choose_rep(a: dict, b: dict) -> dict:
        return a if a.get("published_ts", 0) >= b.get("published_ts", 0) else b

    # 임계치(범용): 너무 낮추면 오탐, 너무 높이면 중복 잔존
    # 경험상 0.52~0.62 사이 튜닝. 기본 0.56 추천.
    THRESH = 0.56

    for it in items:
        placed = False
        best_idx = -1
        best_score = 0.0

        for i, c in enumerate(clusters):
            rep = c["rep"]
            s = score_event_similarity(it["raw_title"], rep["raw_title"])
            if s > best_score:
                best_score = s
                best_idx = i

        # 가장 비슷한 클러스터가 임계치 넘으면 거기에 합류
        if best_idx >= 0 and best_score >= THRESH:
            c = clusters[best_idx]
            # 대표 갱신
            new_rep = choose_rep(c["rep"], it)
            if new_rep is not c["rep"]:
                # 대표가 바뀌면 기존 대표는 others로 이동
                c["others"].append(c["rep"])
                c["rep"] = new_rep
            else:
                c["others"].append(it)
            c["count"] += 1
            placed = True

        if not placed:
            clusters.append(
                {
                    "rep": it,
                    "others": [],
                    "count": 1,
                    "cluster_key": sha256_hex(normalize_title_strong(it["raw_title"])),
                }
            )

    # 대표 최신순 정렬
    clusters.sort(key=lambda x: x["rep"].get("published_ts", 0), reverse=True)
    return clusters


def collect_news_last_24h(session: requests.Session) -> Tuple[List[dict], dict]:
    """
    ✅ 변경점:
    - RSS를 session.get으로 받아 retry/backoff 적용
    - 최근 24시간 필터
    - "사건(event) 단위"로 클러스터링하여 중복 체감 개선
    반환: event_clusters(list), stats(dict)
    """
    now_kst = datetime.now(KST)
    since_kst = now_kst - timedelta(hours=24)

    # (원래 쿼리 유지) - 필요시 환경변수로 빼도 됨
    query = "(마약 OR 마약류 OR 향정 OR 약물) AND (적발 OR 검거 OR 압수 OR 밀수 OR 수사 OR 단속 OR 운전)"
    url = build_google_news_rss_url(query)

    # ✅ session 기반으로 RSS 수신
    feed_text = ""
    try:
        r = session.get(url, timeout=20)
        if r.status_code == 200:
            feed_text = r.text
    except Exception:
        feed_text = ""

    feed = feedparser.parse(feed_text if feed_text else url)

    items = []
    for e in feed.entries:
        raw_title = getattr(e, "title", "").strip()
        link = getattr(e, "link", "").strip()

        # 시간 파싱
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

        title = normalize_title(raw_title)
        publisher = extract_publisher(raw_title)

        items.append(
            {
                "title": title,
                "raw_title": raw_title,
                "publisher": publisher,
                "link": link,
                "published_kst": published_kst.isoformat(timespec="minutes"),
                "published_ts": published_kst.timestamp(),
            }
        )

    # 최신순 정렬(클러스터링 입력)
    items.sort(key=lambda x: x["published_ts"], reverse=True)

    # ✅ 사건 단위 클러스터링
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
    ✅ 출력 형태 변경:
    - "사건 N개 / 기사 M개"
    - 사건별 대표 1개 + (추가 기사 수) 접기/펼치기
    """
    if not event_clusters:
        return "<p>최근 24시간 기준 수집된 뉴스가 없습니다.</p>"

    collected = int(stats.get("collected", 0) or 0)
    events = int(stats.get("events", 0) or 0)

    blocks = []
    for idx, c in enumerate(event_clusters, start=1):
        rep = c["rep"]
        others = c["others"]
        extra_n = len(others)

        pub = f"<span class='meta'>[{escape_html(rep['publisher'])}]</span> " if rep.get("publisher") else ""
        ts = f"<span class='meta'>{escape_html(rep['published_kst'])}</span>"

        # 대표 기사
        head = (
            f"<div class='event-head'>"
            f"<span class='event-no'>[사건 {idx}]</span> "
            f"{pub}<a href='{escape_attr(rep['link'])}' target='_blank' rel='noopener noreferrer'>"
            f"{escape_html(rep['title'])}</a> {ts}"
            f"{f\" <span class='badge small'>+{extra_n}건</span>\" if extra_n else ''}"
            f"</div>"
        )

        # 추가 기사 접기
        if extra_n:
            lis = []
            # 최신순으로 보여주기(대표 제외)
            others_sorted = sorted(others, key=lambda x: x.get("published_ts", 0), reverse=True)
            for o in others_sorted[:30]:
                opub = f"<span class='meta'>[{escape_html(o['publisher'])}]</span> " if o.get("publisher") else ""
                ots = f"<span class='meta'>{escape_html(o['published_kst'])}</span>"
                lis.append(
                    f"<li>{opub}<a href='{escape_attr(o['link'])}' target='_blank' rel='noopener noreferrer'>"
                    f"{escape_html(o['title'])}</a> {ots}</li>"
                )
            tail = (
                "<details class='event-more'>"
                f"<summary>같은 사건으로 묶인 기사 {extra_n}건 보기</summary>"
                f"<ul>{''.join(lis)}</ul>"
                "</details>"
            )
        else:
            tail = ""

        blocks.append(f"<div class='event'>{head}{tail}</div>")

    return (
        f"<div class='kpi'>"
        f"<span class='badge'>기사 {collected}건</span>"
        f"<span class='badge'>사건 {events}개</span>"
        f"</div>"
        f"{''.join(blocks)}"
    )


# =========================
# Site Monitoring (Visualping 대체)
# =========================
@dataclass
class MonitorSpec:
    key: str
    name: str
    url: str
    extractor: Callable[[str], List[str]]  # input: normalized html, output: tokens
    fallback_extractor: Optional[Callable[[str], List[str]]] = None
    soften_dates: bool = True  # ✅ 대상별 날짜/epoch 완화 on/off


def normalize_html(html: str, soften_dates: bool = True) -> str:
    """
    오탐 최소화를 위한 HTML 정규화:
    - script/style 제거
    - 주석 제거
    - 캐시버스터 쿼리스트링 정리
    - 날짜/epoch 류 동적 값 완화 (✅ 선택 가능)
    - 공백 축약
    """
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = str(soup)

    # 주석 제거
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)

    # 캐시버스터 제거(보수적)
    text = re.sub(r"([?&](v|t|timestamp|cache|cb)=)[^&\"'>]+", r"\1", text, flags=re.I)

    if soften_dates:
        # 흔한 동적 값 완화(너무 공격적이면 누락 가능 → 대상별 선택)
        text = re.sub(r"\b20\d{2}[-/.]\d{1,2}[-/.]\d{1,2}\b", "DATE", text)
        text = re.sub(r"\b1[6-9]\d{8,}\b", "EPOCH", text)  # 1600000000~ 류

    # 공백 축약
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
    # 중복 제거 + 상단 제한
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
    """
    SWGDRUG 홈:
    - 링크/문서 제목/버전 표기 등 안정 토큰 위주
    """
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

    # ✅ URL 전체는 변동성이 커서 파일명만 남기는 방식으로 안정화(범용 개선)
    cleaned = []
    for t in tokens:
        if t.lower().endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx")):
            cleaned.append(re.sub(r".*/", "", t))
        else:
            cleaned.append(t)
    return cleaned


def try_extract_cayman_new_products_rendered(url: str) -> Tuple[List[str], str]:
    """
    ✅ Playwright가 없거나 브라우저가 설치되지 않은 환경에서도 죽지 않도록:
    - 성공: (tokens, "")
    - 실패: ([], "에러 메시지")
    """
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=60000)
            html = page.content()
            browser.close()

        tokens = re.findall(r"\bItem\s*No\.?\s*[:#]?\s*(\d{4,8})\b", html, flags=re.I)

        uniq, seen = [], set()
        for t in tokens:
            if t in seen:
                continue
            seen.add(t)
            uniq.append(t)
            if len(uniq) >= 200:
                break
        return uniq, ""
    except Exception as e:
        return [], f"Playwright failed: {type(e).__name__}: {e}"


def extractor_cayman_csl_version_additions(normalized_html: str) -> List[str]:
    """
    CSL Library 페이지에서 'Version info' 및 'Additions' 섹션의 텍스트만 추출하여 토큰화.
    """
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

        m = re.search(rf"({re.escape(title)}.{0,1200})", normalized_html, flags=re.I)
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

    tokens = [t[:2000] for t in tokens]
    return tokens


def extractor_cayman_itemno(normalized_html: str) -> List[str]:
    patterns = [r"\bItem\s*No\.?\s*[:#]?\s*(\d{4,8})\b"]
    tokens = extract_by_regex_list(normalized_html, patterns, max_tokens=120)
    return tokens


def extractor_cayman_fallback(normalized_html: str) -> List[str]:
    patterns = [
        r"property=['\"]og:updated_time['\"][^>]*content=['\"]([^'\"]+)['\"]",
        r"\bLast\s+updated\b[^<]{0,120}",
        r"\bUpdated\b[^<]{0,120}",
    ]
    return extract_by_regex_list(normalized_html, patterns, max_tokens=60)


def monitor_one(
    session: requests.Session,
    spec: MonitorSpec,
    prev_state: dict,
    timeout: int = 25,
) -> dict:
    """
    표준 출력:
      {
        key, name, url,
        ok: bool,
        changed: bool|None,
        error: str,
        token_count: int,
        tokens_head: [..],
        hash: str,
        prev_hash: str,
        fetched_kst: str
      }
    """
    now_kst = datetime.now(KST).isoformat(timespec="minutes")

    prev_entry = (prev_state or {}).get(spec.key, {}) if isinstance(prev_state, dict) else {}
    prev_hash = str(prev_entry.get("hash", "") or "")

    def compute_changed(cur_hash: str) -> Optional[bool]:
        # ✅ 초기 실행/상태 유실 시 changed=None로 표기(원하면 False로 바꿔도 됨)
        if not prev_hash:
            return None
        return cur_hash != prev_hash

    try:
        # ✅ Cayman New Products: Playwright 우선 → 실패 시 HTML fallback
        if spec.key == "cayman_new_products":
            tokens, pw_err = try_extract_cayman_new_products_rendered(spec.url)
            if tokens:
                fp_text = "\n".join(tokens)
                cur_hash = sha256_hex(fp_text)
                return {
                    "key": spec.key,
                    "name": spec.name,
                    "url": spec.url,
                    "ok": True,
                    "changed": compute_changed(cur_hash),
                    "error": "",
                    "token_count": len(tokens),
                    "tokens_head": tokens[:12],
                    "hash": cur_hash,
                    "prev_hash": prev_hash,
                    "fetched_kst": now_kst,
                }

            # Playwright 실패 → HTML 기반 fallback 진행
            r = session.get(spec.url, timeout=timeout)
            if r.status_code != 200:
                return {
                    "key": spec.key,
                    "name": spec.name,
                    "url": spec.url,
                    "ok": False,
                    "changed": False,
                    "error": f"{pw_err} / HTTP {r.status_code}",
                    "token_count": 0,
                    "tokens_head": [],
                    "hash": "",
                    "prev_hash": prev_hash,
                    "fetched_kst": now_kst,
                }

            normalized = normalize_html(r.text, soften_dates=spec.soften_dates)

            # Cayman New Products는 itemno가 가장 범용적으로 잘 먹힘
            tokens = extractor_cayman_itemno(normalized)
            if not tokens:
                tokens = extractor_cayman_fallback(normalized)

            if not tokens:
                return {
                    "key": spec.key,
                    "name": spec.name,
                    "url": spec.url,
                    "ok": False,
                    "changed": False,
                    "error": f"{pw_err} / Token extraction empty (fallback)",
                    "token_count": 0,
                    "tokens_head": [],
                    "hash": "",
                    "prev_hash": prev_hash,
                    "fetched_kst": now_kst,
                }

            fp_text = "\n".join(tokens)
            cur_hash = sha256_hex(fp_text)

            return {
                "key": spec.key,
                "name": spec.name,
                "url": spec.url,
                "ok": True,
                "changed": compute_changed(cur_hash),
                "error": f"{pw_err} (fallback used)",
                "token_count": len(tokens),
                "tokens_head": tokens[:12],
                "hash": cur_hash,
                "prev_hash": prev_hash,
                "fetched_kst": now_kst,
            }

        # ---- 그 외(HTML 기반 감시) ----
        r = session.get(spec.url, timeout=timeout)
        status = r.status_code
        if status != 200:
            return {
                "key": spec.key,
                "name": spec.name,
                "url": spec.url,
                "ok": False,
                "changed": False,
                "error": f"HTTP {status}",
                "token_count": 0,
                "tokens_head": [],
                "hash": "",
                "prev_hash": prev_hash,
                "fetched_kst": now_kst,
            }

        normalized = normalize_html(r.text, soften_dates=spec.soften_dates)

        tokens = spec.extractor(normalized)
        if (not tokens) and spec.fallback_extractor:
            tokens = spec.fallback_extractor(normalized)

        if not tokens:
            return {
                "key": spec.key,
                "name": spec.name,
                "url": spec.url,
                "ok": False,
                "changed": False,
                "error": "Token extraction empty",
                "token_count": 0,
                "tokens_head": [],
                "hash": "",
                "prev_hash": prev_hash,
                "fetched_kst": now_kst,
            }

        fp_text = "\n".join(tokens)
        cur_hash = sha256_hex(fp_text)

        return {
            "key": spec.key,
            "name": spec.name,
            "url": spec.url,
            "ok": True,
            "changed": compute_changed(cur_hash),
            "error": "",
            "token_count": len(tokens),
            "tokens_head": tokens[:12],
            "hash": cur_hash,
            "prev_hash": prev_hash,
            "fetched_kst": now_kst,
        }

    except Exception as e:
        return {
            "key": spec.key,
            "name": spec.name,
            "url": spec.url,
            "ok": False,
            "changed": False,
            "error": f"{type(e).__name__}: {e}",
            "token_count": 0,
            "tokens_head": [],
            "hash": "",
            "prev_hash": prev_hash,
            "fetched_kst": now_kst,
        }


def run_monitoring(session: requests.Session, prev_state: dict) -> Tuple[List[dict], dict, dict]:
    specs = [
        MonitorSpec(
            key="swgdrug_home",
            name="SWGDRUG 홈",
            url="https://swgdrug.org/",
            extractor=extractor_swgdrug,
            soften_dates=True,
        ),
        MonitorSpec(
            key="cayman_csl",
            name="Cayman CSL Library",
            url="https://www.caymanchem.com/forensics/publications/csl",
            extractor=extractor_cayman_csl_version_additions,
            soften_dates=False,  # ✅ CSL은 버전/추가사항에서 날짜가 의미 있을 수 있어 완화 끔
        ),
        MonitorSpec(
            key="cayman_new_products",
            name="Cayman New Products",
            url="https://www.caymanchem.com/forensics/search/productSearch",
            extractor=lambda html: [],  # monitor_one에서 분기 처리
            fallback_extractor=extractor_cayman_itemno,
            soften_dates=True,
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

    # 새 state 생성
    new_state = {}
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
    """
    docs/site_monitor.md (Issue 본문)
    """
    lines = []
    lines.append(f"# 감시 사이트 업데이트 점검 ({summary.get('date_kst','')})")
    lines.append("")
    lines.append(f"- 업데이트 감지: **{summary.get('updated',0)}**")
    lines.append(f"- 실패: **{summary.get('failed',0)}**")
    lines.append("")
    lines.append("## 결과")
    lines.append("")
    lines.append("| 사이트 | 상태 | 변경 | 토큰수 | 비고 |")
    lines.append("|---|---:|---:|---:|---|")

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
        note = r.get("error", "") if (not r.get("ok") or r.get("error")) else ""
        lines.append(f"| {name} | {ok} | {changed} | {token_count} | {escape_md(note)} |")

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
                lines.append(f"- {escape_md(t)}")
            lines.append("")

    return "\n".join(lines).strip() + "\n"


def render_monitor_html(results: List[dict], summary: dict) -> str:
    """
    index.html 하단 섹션(감시 결과)
    - 변경 없음(업데이트 0 + 실패 0)이면 details 접힘
    - 변경/실패 있으면 자동 펼침
    """
    updated = int(summary.get("updated", 0) or 0)
    failed = int(summary.get("failed", 0) or 0)

    open_attr = " open" if (updated > 0 or failed > 0) else ""

    rows = []
    for r in results:
        status = "OK" if r.get("ok") else "FAIL"
        ch = r.get("changed")
        if ch is True:
            changed = "YES"
        elif ch is None:
            changed = "FIRST"
        else:
            changed = "NO"

        note = r.get("error", "") if (not r.get("ok") or r.get("error")) else ""
        rows.append(
            "<tr>"
            f"<td><a href='{escape_attr(r['url'])}' target='_blank' rel='noopener noreferrer'>{escape_html(r['name'])}</a></td>"
            f"<td>{escape_html(status)}</td>"
            f"<td>{escape_html(changed)}</td>"
            f"<td style='text-align:right'>{int(r.get('token_count',0) or 0)}</td>"
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
        "<thead><tr><th>사이트</th><th>상태</th><th>변경</th><th style='text-align:right'>토큰수</th><th>비고</th></tr></thead>"
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

    /* ✅ 뉴스 이벤트 UI */
    .event {{ border: 1px solid #eee; border-radius: 12px; padding: 10px 12px; margin: 10px 0; }}
    .event-head {{ font-size: 14px; }}
    .event-no {{ font-weight: 800; margin-right: 6px; }}
    .event-more summary {{ font-weight: 600; font-size: 13px; }}
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

    # 1) 뉴스 브리핑 (✅ 사건 단위)
    event_clusters, news_stats = collect_news_last_24h(session)
    news_html = render_news_html(event_clusters, news_stats)

    # 2) 감시(전날 state 로드 → 비교) (✅ session 기반 로딩)
    prev_state = load_prev_state(session)
    results, new_state, meta = run_monitoring(session, prev_state)

    summary = meta.get("summary", {})
    monitor_html = render_monitor_html(results, summary)

    # 3) 산출물 저장
    state_out = {"meta": meta, "sites": new_state}
    write_json(STATE_JSON, state_out)

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
