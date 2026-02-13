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


def safe_get_json(url: str, timeout: int = 20) -> Optional[dict]:
    if not url:
        return None
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def load_prev_state() -> dict:
    """
    우선순위:
      1) SITE_STATE_URL(gh-pages raw)에서 전날 상태 로드 시도
      2) 로컬 docs/site_state.json
      3) 없으면 빈 dict

    주의:
      저장 구조가 {"meta":..., "sites":{...}} 이므로,
      항상 sites를 반환하도록 보정한다.
    """
    prev = safe_get_json(SITE_STATE_URL) if SITE_STATE_URL else None
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
# News Briefing
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


def jaccard_sim(a: str, b: str) -> float:
    sa = set(re.findall(r"[0-9A-Za-z가-힣]+", a.lower()))
    sb = set(re.findall(r"[0-9A-Za-z가-힣]+", b.lower()))
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def collect_news_last_24h(session: requests.Session) -> Tuple[List[dict], dict]:
    """
    - Google News RSS 검색
    - 최근 24시간만
    - 제목 유사도(Jaccard) 중복 제거
    """
    now_kst = datetime.now(KST)
    since_kst = now_kst - timedelta(hours=24)

    query = "(마약 OR 마약류 OR 향정 OR 약물) AND (적발 OR 검거 OR 압수 OR 밀수 OR 수사 OR 단속)"
    url = build_google_news_rss_url(query)

    feed = feedparser.parse(url)
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
            # 시간 정보가 없으면 제외(오탐/누락보다 안정 우선)
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

    # 최신순 정렬
    items.sort(key=lambda x: x["published_ts"], reverse=True)

    # 중복 제거(Jaccard)
    deduped = []
    for it in items:
        is_dup = False
        for kept in deduped:
            if jaccard_sim(it["title"], kept["title"]) >= 0.72:
                is_dup = True
                break
        if not is_dup:
            deduped.append(it)

    stats = {
        "collected": len(items),
        "deduped": len(deduped),
        "since_kst": since_kst.isoformat(timespec="minutes"),
        "now_kst": now_kst.isoformat(timespec="minutes"),
        "rss_url": url,
    }
    return deduped, stats


def render_news_html(news: List[dict], stats: dict) -> str:
    if not news:
        return "<p>최근 24시간 기준 수집된 뉴스가 없습니다.</p>"

    lis = []
    for n in news:
        pub = f"<span class='meta'>[{escape_html(n['publisher'])}]</span> " if n["publisher"] else ""
        ts = f"<span class='meta'>{escape_html(n['published_kst'])}</span>"
        lis.append(
            f"<li>{pub}<a href='{escape_attr(n['link'])}' target='_blank' rel='noopener noreferrer'>{escape_html(n['title'])}</a> {ts}</li>"
        )

    return (
        f"<div class='kpi'>"
        f"<span class='badge'>뉴스 {stats.get('collected',0)}건</span>"
        f"<span class='badge'>중복 제거 후 {stats.get('deduped',0)}건</span>"
        f"</div>"
        f"<ul>{''.join(lis)}</ul>"
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


def normalize_html(html: str) -> str:
    """
    오탐 최소화를 위한 HTML 정규화:
    - script/style 제거
    - 주석 제거
    - 캐시버스터 쿼리스트링 정리
    - 날짜/epoch 류 동적 값 완화
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

    # 흔한 동적 값 완화(너무 공격적이면 오히려 누락 가능 → 보수적으로)
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
    return extract_by_regex_list(normalized_html, patterns, max_tokens=140)

def extractor_cayman_new_products_rendered(url: str) -> List[str]:
    """
    Cayman New Products는 requests로 API/JSON 호출이 HTML로 회수되므로,
    Playwright로 렌더링 후 Item No 기반 토큰을 생성한다.
    """
    from playwright.sync_api import sync_playwright
    import re

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
    return uniq

def extractor_cayman_csl_version_additions(normalized_html: str) -> List[str]:
    """
    CSL Library 페이지에서 'Version info' 및 'Additions' 섹션의 텍스트만 추출하여 토큰화.
    """
    soup = BeautifulSoup(normalized_html, "html.parser")

    def collect_section_text(title: str) -> str:
        # 1) heading(h1~h6)에서 title 포함하는 요소 찾기
        heading = None
        for tag in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
            t = tag.get_text(" ", strip=True)
            if t and title.lower() in t.lower():
                heading = tag
                break

        if heading:
            # heading 이후 다음 heading 전까지의 텍스트 수집
            texts = []
            for sib in heading.find_all_next():
                if sib.name in ["h1", "h2", "h3", "h4", "h5", "h6"]:
                    break
                if sib.name in ["script", "style", "noscript"]:
                    continue
                txt = sib.get_text(" ", strip=True) if hasattr(sib, "get_text") else ""
                if txt:
                    texts.append(txt)
                if len(" ".join(texts)) > 2000:  # 과도한 수집 제한
                    break
            return " ".join(texts).strip()

        # 2) fallback: 원문에서 title 근처 1200자 슬라이스
        m = re.search(rf"({re.escape(title)}.{0,1200})", normalized_html, flags=re.I)
        if m:
            # 태그 제거 후 텍스트화(간단)
            chunk = re.sub(r"<[^>]+>", " ", m.group(1))
            chunk = re.sub(r"\s+", " ", chunk).strip()
            return chunk

        return ""

    vi = collect_section_text("Version info")
    ad = collect_section_text("Additions")

    # 토큰 구성: 비교 안정성을 위해 키를 붙여 구분
    tokens = []
    if vi:
        tokens.append("Version info:" + vi)
    if ad:
        tokens.append("Additions:" + ad)

    # 너무 길면 해시가 불안정해질 수 있어 절단(운영 안정성)
    tokens = [t[:2000] for t in tokens]

    # 최소 1개라도 있어야 함
    return tokens

def extractor_cayman_itemno(normalized_html: str) -> List[str]:
    """
    Cayman 계열:
    - Item No 기반 토큰 상단 N개 추출
    """
    # Item No. 12345 / Item No 12345 / Item No: 12345 등
    patterns = [r"\bItem\s*No\.?\s*[:#]?\s*(\d{4,8})\b"]
    tokens = extract_by_regex_list(normalized_html, patterns, max_tokens=80)
    return tokens


def extractor_cayman_fallback(normalized_html: str) -> List[str]:
    """
    Cayman fallback:
    - og:updated_time 또는 last updated 류 텍스트 단서
    """
    patterns = [
        r"property=['\"]og:updated_time['\"][^>]*content=['\"]([^'\"]+)['\"]",
        r"\bLast\s+updated\b[^<]{0,80}",
        r"\bUpdated\b[^<]{0,80}",
    ]
    return extract_by_regex_list(normalized_html, patterns, max_tokens=40)


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
        changed: bool,
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

    try:
        # ✅ Cayman New Products: Playwright 렌더링 기반 감시
        if spec.key == "cayman_new_products":
            tokens = extractor_cayman_new_products_rendered(spec.url)

            if not tokens:
                return {
                    "key": spec.key,
                    "name": spec.name,
                    "url": spec.url,
                    "ok": False,
                    "changed": False,
                    "error": "Rendered token extraction empty",
                    "token_count": 0,
                    "tokens_head": [],
                    "hash": "",
                    "prev_hash": prev_hash,
                    "fetched_kst": now_kst,
                }

            fp_text = "\n".join(tokens)
            cur_hash = sha256_hex(fp_text)
            changed = (prev_hash != "") and (cur_hash != prev_hash)

            return {
                "key": spec.key,
                "name": spec.name,
                "url": spec.url,
                "ok": True,
                "changed": changed,
                "error": "",
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

        normalized = normalize_html(r.text)

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
        changed = (prev_hash != "") and (cur_hash != prev_hash)

        return {
            "key": spec.key,
            "name": spec.name,
            "url": spec.url,
            "ok": True,
            "changed": changed,
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
        ),
        MonitorSpec(
            key="cayman_csl",
            name="Cayman CSL Library",
            url="https://www.caymanchem.com/forensics/publications/csl",
            extractor=extractor_cayman_csl_version_additions,
        ),

        MonitorSpec(
            key="cayman_new_products",
            name="Cayman New Products",
            url="https://www.caymanchem.com/forensics/search/productSearch",
            extractor=lambda html: [],  # 사용 안 함(아래 monitor_one 분기에서 return)
        ),

    ]

    results: List[dict] = []
    for spec in specs:
        results.append(monitor_one(session, spec, prev_state))
        time.sleep(1.0)  # 과도한 연속 요청 완화

    updated = sum(1 for r in results if r.get("ok") and r.get("changed"))
    failed = sum(1 for r in results if not r.get("ok"))

    summary = {
        "date_kst": datetime.now(KST).strftime("%Y-%m-%d"),
        "updated": updated,
        "failed": failed,
    }

    # 새 state 생성
    new_state = {}
    for r in results:
        # ok인 경우만 hash/state 저장(실패 상태를 state로 굳히지 않기 위함)
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
        changed = "YES" if r.get("changed") else "NO"
        token_count = str(r.get("token_count", 0) or 0)
        note = r.get("error", "") if not r.get("ok") else ""
        lines.append(f"| {name} | {ok} | {changed} | {token_count} | {escape_md(note)} |")

    # 변경 상세(헤드 토큰)
    lines.append("")
    lines.append("## 변경 상세(상단 토큰)")
    lines.append("")
    for r in results:
        if r.get("ok") and r.get("changed"):
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
        changed = "YES" if r.get("changed") else "NO"
        note = r.get("error", "") if not r.get("ok") else ""
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
    # Issue 본문 최소 이스케이프
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
    news, news_stats = collect_news_last_24h(session)
    news_html = render_news_html(news, news_stats)

    # 2) 감시(전날 state 로드 → 비교)
    prev_state = load_prev_state()
    results, new_state, meta = run_monitoring(session, prev_state)

    summary = meta.get("summary", {})
    monitor_html = render_monitor_html(results, summary)

    # 3) 산출물 저장
    # (1) state 저장
    state_out = {"meta": meta, "sites": new_state}
    write_json(STATE_JSON, state_out)

    # (2) Issue 본문(md) 저장
    md = render_monitor_md(results, summary)
    with open(MONITOR_MD, "w", encoding="utf-8") as f:
        f.write(md)

    # (3) monitor summary json 저장 (workflow에서 Issue 생성 조건 판단용)
    write_json(MONITOR_SUMMARY_JSON, summary)

    # (4) index.html 저장
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
