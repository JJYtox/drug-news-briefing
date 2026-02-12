import feedparser
import os
from datetime import datetime, timedelta
import pytz
import html
import re
import json
import hashlib
import requests
from bs4 import BeautifulSoup

# -----------------------------
# 기본 설정
# -----------------------------
os.makedirs("docs", exist_ok=True)

TIMEZONE = pytz.timezone("Asia/Seoul")
now = datetime.now(TIMEZONE)
cutoff = now - timedelta(hours=24)

RSS_URL = (
    "https://news.google.com/rss/search?q="
    "(마약+OR+마약류+OR+향정+OR+약물)"
    "+AND+(적발+OR+검거+OR+압수+OR+밀수+OR+수사+OR+단속)"
    "&hl=ko&gl=KR&ceid=KR:ko"
)

SITES = [
    # SWGDRUG: 홈 상단 업데이트 안내 문구만 감시
    {
        "name": "SWGDRUG (Home Updates)",
        "mode": "html_regex",
        "url": "https://swgdrug.org/",
        "patterns": [
            r"Last\s+Update\s*[:\-]?\s*[A-Za-z]+\s+\d{4}",
            r"Updated\s*[:\-]?\s*[A-Za-z]+\s+\d{4}",
            r"Update(d)?\s*[:\-]?\s*\d{4}",
        ],
    },
    {
        "name": "Cayman CSL (Library Update)",
        "mode": "html_regex",
        "url": "https://www.caymanchem.com/forensics/publications/csl",
        "patterns": [r"Version", r"change\s+log", r"Release", r"updated", r"added"],
    },
    {
        "name": "Cayman New Products (Forensics search)",
        "mode": "cayman_product_list",
        "url": "https://www.caymanchem.com/forensics/search/productSearch",
    },
]

TIMEOUT = 25
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"}


# -----------------------------
# 유틸: 해시/HTML 파싱
# -----------------------------
def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def fetch_html(url: str) -> str:
    r = requests.get(url, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return r.text


def html_text_compact(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def fingerprint_html_regex(url: str, patterns: list[str]) -> tuple[str, dict]:
    html_raw = fetch_html(url)
    text = html_text_compact(html_raw)

    hits = []
    for p in patterns:
        m = re.search(p, text, flags=re.IGNORECASE)
        hits.append(m.group(0) if m else "")

    key = " | ".join(hits)

    # 패턴이 하나도 안 잡히면(구조 변경 등) 폴백: 상단 일부만 사용(오탐 최소화)
    if not key.strip():
        key = text[:6000]

    return sha(key), {"matches": hits}


def fingerprint_cayman_product_list(url: str) -> tuple[str, dict]:
    html_raw = fetch_html(url)
    text = html_text_compact(html_raw)

    items = []
    for m in re.finditer(r"Item\s+No\.\s*\d{4,6}", text, flags=re.IGNORECASE):
        start = max(0, m.start() - 80)
        end = min(len(text), m.end() + 80)
        items.append(text[start:end])
        if len(items) >= 5:
            break

    if items:
        key = " || ".join(items)
        return sha(key), {"top_items": items}

    # 폴백: 텍스트 일부 해시
    return sha(text[:20000]), {"top_items": []}


# -----------------------------
# 0) 사이트 감시 (전날 상태 비교 → site_state.json / site_monitor.md 생성)
# -----------------------------
SITE_STATE_URL = os.environ.get("SITE_STATE_URL", "").strip()
prev_state = {}

if SITE_STATE_URL:
    try:
        rr = requests.get(SITE_STATE_URL, headers=UA, timeout=TIMEOUT)
        if rr.status_code == 200:
            prev_state = rr.json()
    except Exception:
        prev_state = {}

site_results = []
new_state = {}

for s in SITES:
    name, mode, url = s["name"], s["mode"], s["url"]
    changed = False
    detail = {}
    fp = ""

    try:
        if mode == "html_regex":
            fp, detail = fingerprint_html_regex(url, s.get("patterns", []))
        elif mode == "cayman_product_list":
            fp, detail = fingerprint_cayman_product_list(url)
        else:
            raise ValueError("Unknown mode")

        prev_fp = (prev_state.get(name) or {}).get("fingerprint")
        changed = (prev_fp != fp) if prev_fp else True  # 첫 실행은 True(기준선 생성)

    except Exception as e:
        detail = {"error": str(e)}
        fp = ""
        changed = False

    new_state[name] = {
        "url": url,
        "mode": mode,
        "fingerprint": fp,
        "detail": detail,
        "checked_at": now.strftime("%Y-%m-%d %H:%M"),
    }
    site_results.append({"name": name, "url": url, "changed": changed, "detail": detail})

with open("docs/site_state.json", "w", encoding="utf-8") as f:
    json.dump(new_state, f, ensure_ascii=False, indent=2)

changed_sites = [x for x in site_results if x["changed"]]
failed_sites = [x for x in site_results if isinstance(x["detail"], dict) and x["detail"].get("error")]

lines = []
lines.append("## ■ 감시 대상 사이트 업데이트 점검")
lines.append(f"- 점검 시각: {now.strftime('%Y-%m-%d %H:%M')} (Asia/Seoul)")
lines.append(f"- 업데이트 감지: **{len(changed_sites)}곳**")
lines.append(f"- 점검 실패: **{len(failed_sites)}곳**")
lines.append("")

if not changed_sites:
    lines.append("> 금일 점검 기준으로 ‘새 업데이트 감지’된 사이트가 없습니다.")
else:
    lines.append("### 업데이트 감지 목록")
    for x in changed_sites:
        lines.append(f"- **{x['name']}**: {x['url']}")

if failed_sites:
    lines.append("")
    lines.append("### 점검 실패(접속/파싱 오류)")
    for x in failed_sites:
        lines.append(f"- **{x['name']}**: {x['detail'].get('error','')}")

with open("docs/site_monitor.md", "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")


# -----------------------------
# 유틸: 언론사 분리
# -----------------------------
def split_source(title: str):
    """
    제목 끝의 ' - 언론사' 또는 ' | 언론사' 형태를 분리.
    반환: (base_title, source_or_empty)
    """
    t = title.strip()
    t = re.sub(r"\s+", " ", t)

    m = re.search(r"\s*[-|–]\s*([^-|–]{1,30})$", t)
    if m:
        source = m.group(1).strip()
        base = re.sub(r"\s*[-|–]\s*[^-|–]{1,30}$", "", t).strip()
        return base, source
    return t, ""


# -----------------------------
# 유틸: 토크나이즈 + 유사도
# -----------------------------
def tokenize_ko(s: str) -> list[str]:
    s = re.sub(r"[\[\]\(\)【】<>\"'“”‘’]", " ", s)
    s = re.sub(r"[^0-9A-Za-z가-힣\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip().lower()

    tokens = s.split()
    stop = {"관련", "속보", "단독", "종합", "영상", "포토", "기자", "뉴스"}
    tokens = [t for t in tokens if t not in stop and len(t) >= 2]
    return tokens


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# -----------------------------
# 1) RSS 수집
# -----------------------------
feed = feedparser.parse(RSS_URL)

items_raw = []
for e in getattr(feed, "entries", []):
    dt_struct = getattr(e, "published_parsed", None) or getattr(e, "updated_parsed", None)
    if not dt_struct:
        continue

    published = datetime(*dt_struct[:6], tzinfo=pytz.utc).astimezone(TIMEZONE)
    if published < cutoff:
        continue

    title = getattr(e, "title", "").strip()
    link = getattr(e, "link", "").strip()
    if not title or not link:
        continue

    items_raw.append((published, title, link))


# -----------------------------
# 2) 강화 중복 제거(유사도)
# -----------------------------
SIM_THRESHOLD = 0.58  # 중복이 너무 많을 때는 0.55~0.60 권장

deduped = []
seen_keys = []  # [(token_set, date), ...]

for published, title, link in items_raw:
    base, source = split_source(title)
    day_key = published.date()

    tok = set(tokenize_ko(base))
    if not tok:
        deduped.append((published, base, link, source))
        continue

    is_dup = False
    for prev_tok, prev_day in seen_keys:
        if abs((day_key - prev_day).days) > 1:
            continue
        if jaccard(tok, prev_tok) >= SIM_THRESHOLD:
            is_dup = True
            break

    if is_dup:
        continue

    seen_keys.append((tok, day_key))
    deduped.append((published, base, link, source))

items = sorted(deduped, reverse=True)


# -----------------------------
# 3) HTML 생성
# -----------------------------
def render():
    page_title = f"마약류 일일 브리핑 ({now.strftime('%Y-%m-%d')} KST)"
    updated = now.strftime("%Y-%m-%d %H:%M")

    # "변경 없음이면 자동 접기" 조건
    has_site_change = (len(changed_sites) > 0) or (len(failed_sites) > 0)
    details_open_attr = " open" if has_site_change else ""

    head = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(page_title)}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height: 1.5; }}
    .meta {{ color: #666; font-size: 12px; margin-bottom: 16px; }}
    ul {{ padding-left: 18px; }}
    li {{ margin: 10px 0; }}
    a {{ text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .time {{ color: #777; font-size: 12px; margin-left: 6px; }}
    .empty {{ color: #444; padding: 12px; background: #f6f6f6; border-radius: 8px; }}
    .card {{ padding: 12px; background: #f6f6f6; border-radius: 8px; margin: 12px 0 0 0; }}
    .sub {{ color: #666; font-size: 12px; margin-top: 6px; }}
    .ok {{ color: #1a7f37; font-weight: 600; }}
    .warn {{ color: #b42318; font-weight: 600; }}
    details {{ margin-top: 22px; }}
    summary {{ cursor: pointer; font-weight: 700; }}
    .tag {{ display:inline-block; border:1px solid #ddd; border-radius:10px; padding:1px 8px; font-size:12px; color:#555; margin-left:6px; }}
  </style>
</head>
<body>
"""

    # -----------------------------
    # (1) 뉴스 섹션: 상단
    # -----------------------------
    news_head = f"""
  <h2>■ 최근 24시간 마약류 관련 주요 기사</h2>
  <div class="meta">업데이트: {html.escape(updated)} (Asia/Seoul 기준)</div>
"""

    if not items:
        news_body = """  <div class="empty">최근 24시간 기준으로 수집된 기사가 없습니다.</div>\n"""
    else:
        news_body = "  <ul>\n"
        for pub, t, link, source in items:
            pub_s = pub.strftime("%Y-%m-%d %H:%M")
            badge = (
                f" <span class='tag'>{html.escape(source)}</span>"
                if source else ""
            )
            news_body += (
                f"    <li><a href=\"{html.escape(link)}\" target=\"_blank\" rel=\"noopener noreferrer\">"
                f"{html.escape(t)}</a>{badge}<span class=\"time\">({html.escape(pub_s)})</span></li>\n"
            )
        news_body += "  </ul>\n"

    # -----------------------------
    # (2) 사이트 감시 섹션: 하단 + 변경 없음이면 자동 접기
    # -----------------------------
    # summary 문구에 핵심 수치 표시
    summary_line = (
        f"■ 감시 대상 사이트 업데이트 점검 "
        f"(업데이트 {len(changed_sites)}곳 / 실패 {len(failed_sites)}곳)"
    )

    site_block = f"""
  <details{details_open_attr}>
    <summary>{html.escape(summary_line)}</summary>
    <div class="card">
      <div class="sub">점검 시각: {html.escape(updated)} (Asia/Seoul)</div>
      <div style="margin-top:8px;">
        업데이트 감지:
        <span class="{'warn' if len(changed_sites) else 'ok'}">{len(changed_sites)}곳</span>
        /
        점검 실패:
        <span class="{'warn' if len(failed_sites) else 'ok'}">{len(failed_sites)}곳</span>
      </div>
"""

    if not changed_sites and not failed_sites:
        site_block += """      <div class="sub" style="margin-top:10px;">변경 없음(업데이트 감지 및 점검 실패 없음)</div>\n"""
    else:
        if changed_sites:
            site_block += "      <div class='sub' style='margin-top:10px;'>업데이트 감지 목록</div>\n"
            site_block += "      <ul>\n"
            for x in changed_sites:
                site_block += (
                    f"        <li><a href=\"{html.escape(x['url'])}\" target=\"_blank\" rel=\"noopener noreferrer\">"
                    f"{html.escape(x['name'])}</a></li>\n"
                )
            site_block += "      </ul>\n"

        if failed_sites:
            site_block += "      <div class='sub' style='margin-top:10px;'>점검 실패(접속/파싱 오류)</div>\n"
            site_block += "      <ul>\n"
            for x in failed_sites:
                err = x["detail"].get("error", "") if isinstance(x.get("detail"), dict) else ""
                site_block += (
                    f"        <li>{html.escape(x['name'])}<span class='tag'>ERROR</span>"
                    f"<div class='sub'>{html.escape(err)}</div></li>\n"
                )
            site_block += "      </ul>\n"

    site_block += """    </div>
  </details>
"""

    tail = """
</body>
</html>
"""

    return head + news_head + news_body + site_block + tail


out_path = "docs/index.html"
with open(out_path, "w", encoding="utf-8") as f:
    f.write(render())

print(f"Wrote {out_path} with {len(items)} items. (raw: {len(items_raw)})")
print("Wrote docs/site_state.json and docs/site_monitor.md")
