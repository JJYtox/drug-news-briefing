import feedparser
import os
from datetime import datetime, timedelta
import pytz
import html
import re

os.makedirs("docs", exist_ok=True)

RSS_URL = (
    "https://news.google.com/rss/search?q="
    "(마약+OR+마약류+OR+향정+OR+약물)"
    "+AND+(적발+OR+검거+OR+압수+OR+밀수+OR+수사+OR+단속)"
    "&hl=ko&gl=KR&ceid=KR:ko"
)

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
