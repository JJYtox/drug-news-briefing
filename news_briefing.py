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

os.makedirs("docs", exist_ok=True)

RSS_URL = (
    "https://news.google.com/rss/search?q="
    "(마약+OR+마약류+OR+향정+OR+약물)"
    "+AND+(적발+OR+검거+OR+압수+OR+밀수+OR+수사+OR+단속)"
    "&hl=ko&gl=KR&ceid=KR:ko"
)

SITES = [
    # SWGDRUG: 'Last Update ...' 문구만 뽑아 지문(fingerprint) 생성
    {"name": "SWGDRUG Bulletins", "mode": "html_regex", "url": "https://www.swgdrug.org/bulletin.htm",
     "patterns": [r"Last\s+Update\s+[A-Za-z]+\s+\d{4}"]},

    {"name": "SWGDRUG Approved Recommendations", "mode": "html_regex", "url": "https://www.swgdrug.org/approved.htm",
     "patterns": [r"Last\s+Update\s+[A-Za-z]+\s+\d{4}", r"Edition\s+\d+(\.\d+)?\s*\([0-9A-Za-z\-]+\)"]},

    {"name": "SWGDRUG Monographs", "mode": "html_regex", "url": "https://www.swgdrug.org/monographs.htm",
     "patterns": [r"Last\s+Update\s+[A-Za-z]+\s+\d{4}"]},

    # Cayman CSL: 페이지에서 'Version' / 'Change log' 관련 키워드 주변 텍스트를 뽑아 지문 생성
    {"name": "Cayman CSL (Library Update)", "mode": "html_regex", "url": "https://www.caymanchem.com/forensics/publications/csl",
     "patterns": [r"Version", r"change\s+log", r"Release", r"updated", r"added"]},

    # Cayman New products: 상단 일부 제품/Item No. 추출(가능할 때) → 불가하면 페이지 본문 해시로 대체
    {"name": "Cayman New Products (Forensics search)", "mode": "cayman_product_list", "url": "https://www.caymanchem.com/forensics/search/productSearch"},
]

TIMEOUT = 25
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"}

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
    # 패턴이 하나도 안 잡히면(사이트 구조 변경 등) 전체 텍스트 일부로 폴백
    if not key.strip():
        key = text[:20000]
    return sha(key), {"matches": hits}

def fingerprint_cayman_product_list(url: str) -> tuple[str, dict]:
    html_raw = fetch_html(url)
    text = html_text_compact(html_raw)

    # "Item No." 기반으로 상단 5개 정도만 잡아봄(성공하면 매우 안정적)
    # (페이지 구조가 바뀌면 매칭이 줄어들 수 있으니 폴백 포함)
    items = []
    # 예: "Item No. 44822" 같은 토큰을 기준으로 주변 80자 정도를 뽑음
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

# --- 사이트 감시: 전날 상태 읽기 ---
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
        changed = (prev_fp != fp) if prev_fp else True  # 첫 실행은 True로 처리(초기 기준선 설정)

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

# 상태 저장(gh-pages에 같이 올라가야 다음날 비교 가능)
with open("docs/site_state.json", "w", encoding="utf-8") as f:
    json.dump(new_state, f, ensure_ascii=False, indent=2)

# 이슈 본문(사이트 감시 중심)
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


TIMEZONE = pytz.timezone("Asia/Seoul")
now = datetime.now(TIMEZONE)
cutoff = now - timedelta(hours=24)

feed = feedparser.parse(RSS_URL)

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
    # 괄호/특수문자 제거, 한글/영문/숫자만 남김
    s = re.sub(r"[\[\]\(\)【】<>\"'“”‘’]", " ", s)
    s = re.sub(r"[^0-9A-Za-z가-힣\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip().lower()

    tokens = s.split()

    # 너무 흔한 단어 제거(필요 시 추가)
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
seen_keys = []  # [(token_set, date_ymd), ...]

for published, title, link in items_raw:
    base, source = split_source(title)

    # 같은 날(또는 1일 차이)만 비교: 과도 병합 방지
    day_key = published.date()

    tok = set(tokenize_ko(base))
    if not tok:
        # 토큰이 비면(극단적으로 짧은 제목) 그냥 통과
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
  </style>
</head>
<body>
  <h2>■ 최근 24시간 마약류 관련 주요 기사</h2>
  <div class="meta">업데이트: {html.escape(updated)} (Asia/Seoul 기준)</div>
"""
    if not items:
        body = """  <div class="empty">최근 24시간 기준으로 수집된 기사가 없습니다.</div>\n"""
    else:
        body = "  <ul>\n"
        for pub, t, link, source in items:
            pub_s = pub.strftime("%Y-%m-%d %H:%M")
            badge = (
                f" <span style='border:1px solid #ddd;border-radius:10px;"
                f"padding:1px 8px;font-size:12px;color:#555;'>"
                f"{html.escape(source)}</span>"
                if source else ""
            )
            body += (
                f"    <li><a href=\"{html.escape(link)}\" target=\"_blank\" rel=\"noopener noreferrer\">"
                f"{html.escape(t)}</a>{badge}<span class=\"time\">({html.escape(pub_s)})</span></li>\n"
            )
        body += "  </ul>\n"

    tail = """
</body>
</html>
"""
    return head + body + tail

out_path = "docs/index.html"
with open(out_path, "w", encoding="utf-8") as f:
    f.write(render())

print(f"Wrote {out_path} with {len(items)} items. (raw: {len(items_raw)})")
