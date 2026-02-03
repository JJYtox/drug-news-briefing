import feedparser
import os
os.makedirs("docs", exist_ok=True)

from datetime import datetime, timedelta
import pytz
import html
import re

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

items = []
for e in getattr(feed, "entries", []):
    if not hasattr(e, "published_parsed"):
        continue
    published = datetime(*e.published_parsed[:6], tzinfo=pytz.utc).astimezone(TIMEZONE)
    if published < cutoff:
        continue
    title = getattr(e, "title", "").strip()
    link = getattr(e, "link", "").strip()
    if not title or not link:
        continue
    items.append((published, title, link))

def split_source(title: str):
    """
    제목 끝의 ' - 언론사' 또는 ' | 언론사' 형태를 분리.
    반환: (base_title, source_or_empty)
    """
    t = title.strip()
    t = re.sub(r"\s+", " ", t)

    # 끝부분 구분자(-, |, –) 뒤 1~30자(언론사명으로 가정)
    m = re.search(r"\s*[-|–]\s*([^-|–]{1,30})$", t)
    if m:
        source = m.group(1).strip()
        base = re.sub(r"\s*[-|–]\s*[^-|–]{1,30}$", "", t).strip()
        return base, source
    return t, ""


seen = set()
deduped = []

for published, title, link in items:
    base, source = split_source(title)
    key = base  # 중복 판정은 언론사 제거된 base 제목 기준
    if key in seen:
        continue
    seen.add(key)
    # items를 (published, base_title, link, source) 형태로 확장
    deduped.append((published, base, link, source))

items = deduped



items.sort(reverse=True)

def render():
    title = f"마약류 일일 브리핑 ({now.strftime('%Y-%m-%d')} KST)"
    updated = now.strftime("%Y-%m-%d %H:%M")

    head = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(title)}</title>
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

print(f"Wrote {out_path} with {len(items)} items.")
