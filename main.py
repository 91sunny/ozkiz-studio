import os
import io
import time
import hmac
import json
import base64
import hashlib
import secrets
import httpx
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Cookie, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="OzKiz Studio")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── 환경변수 ──────────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
SESSION_SECRET       = os.getenv("SESSION_SECRET", "changeme-set-this-in-env")
ALLOWED_DOMAIN       = "openhan.kr"
BASE_URL             = os.getenv("BASE_URL", "http://localhost:8001")

GEMINI_KEY   = os.getenv("GEMINI_API_KEY", "")
NOTION_KEY   = os.getenv("NOTION_API_KEY", "")
NOTION_DB_ID = os.getenv("NOTION_DATABASE_ID", "")
NOTION_NAME_PROP = os.getenv("NOTION_NAME_PROPERTY", "제품명")
NOTION_HEADERS = {
    "Authorization": f"Bearer {NOTION_KEY}",
    "Notion-Version": "2022-06-28",
    "Content-Type": "application/json",
} if NOTION_KEY else {}

# ─── Gemini 초기화 ─────────────────────────────────────────────────────────────
ai_available = False
gemini_client = None
if GEMINI_KEY:
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_KEY)
        gemini_client = genai.GenerativeModel("gemini-2.0-flash")
        ai_available = True
    except Exception:
        try:
            from google import genai as gai
            gemini_client = gai.Client(api_key=GEMINI_KEY)
            ai_available = True
        except Exception:
            pass

# ─── 세션 (HMAC 서명 쿠키, stateless) ────────────────────────────────────────
_OAUTH_STATES: dict = {}

def _make_token(email: str) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"email": email, "exp": time.time() + 86400 * 30}).encode()
    ).decode()
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def _verify_token(token: str):
    try:
        payload, sig = token.rsplit(".", 1)
        expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload + "=="))
        if data.get("exp", 0) < time.time():
            return None
        return data.get("email")
    except Exception:
        return None

def _require_auth(session: str = Cookie(default="")):
    email = _verify_token(session)
    if not email:
        raise HTTPException(status_code=401, detail="로그인 필요")
    return email

# ─── 노션 캐시 (지연 로딩) ────────────────────────────────────────────────────
_notion_cache: list = []
_cache_loaded_at: float = 0
_CACHE_TTL = 600  # 10분

async def _ensure_notion_cache():
    global _notion_cache, _cache_loaded_at
    if _notion_cache and time.time() - _cache_loaded_at < _CACHE_TTL:
        return
    if not NOTION_KEY or not NOTION_DB_ID:
        return
    products = []
    has_more, cursor = True, None
    _ALLOWED = {"품평회", "생산 요청(국내)", "생산 요청(해외)"}
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            while has_more:
                body = {"page_size": 100}
                if cursor:
                    body["start_cursor"] = cursor
                res = await client.post(
                    f"https://api.notion.com/v1/databases/{NOTION_DB_ID}/query",
                    headers=NOTION_HEADERS, json=body
                )
                data = res.json()
                for page in data.get("results", []):
                    props = page.get("properties", {})
                    name = ""
                    for pval in props.values():
                        if pval.get("type") == "title":
                            t = pval.get("title", [])
                            if t:
                                name = t[0].get("plain_text", "").strip()
                            break
                    if not name:
                        continue
                    status_raw = ""
                    stp = props.get("진행상태")
                    if stp:
                        if stp.get("type") == "status" and stp.get("status"):
                            status_raw = stp["status"].get("name", "")
                        elif stp.get("type") == "select" and stp.get("select"):
                            status_raw = stp["select"].get("name", "")
                    if status_raw not in _ALLOWED:
                        continue
                    products.append({
                        "page_id": page.get("id", ""),
                        "name": name,
                        "status": status_raw,
                    })
                has_more = data.get("has_more", False)
                cursor = data.get("next_cursor")
        _notion_cache = products
        _cache_loaded_at = time.time()
        print(f"[Notion] {len(products)}개 캐시")
    except Exception as e:
        print(f"[Notion] 캐시 오류: {e}")

# ─── 정적 파일 ────────────────────────────────────────────────────────────────
import pathlib
_STATIC = pathlib.Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

# ─── 페이지 ───────────────────────────────────────────────────────────────────
@app.get("/login")
async def login_page():
    return HTMLResponse((_STATIC / "login.html").read_text(encoding="utf-8"))

@app.get("/")
async def index(session: str = Cookie(default="")):
    if not _verify_token(session):
        return RedirectResponse("/login")
    return HTMLResponse((_STATIC / "index.html").read_text(encoding="utf-8"))

# ─── Google OAuth ──────────────────────────────────────────────────────────────
@app.get("/api/auth/google")
async def google_auth():
    if not GOOGLE_CLIENT_ID:
        return RedirectResponse("/")
    state = secrets.token_urlsafe(16)
    _OAUTH_STATES[state] = True
    redirect_uri = f"{BASE_URL}/api/auth/callback"
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code&scope=openid%20email%20profile"
        f"&state={state}&hd={ALLOWED_DOMAIN}"
    )
    return RedirectResponse(url)

@app.get("/api/auth/callback")
async def google_callback(code: str = "", state: str = "", error: str = ""):
    if error or state not in _OAUTH_STATES:
        return RedirectResponse("/login?error=auth_failed")
    del _OAUTH_STATES[state]
    redirect_uri = f"{BASE_URL}/api/auth/callback"
    async with httpx.AsyncClient() as client:
        token_res = await client.post("https://oauth2.googleapis.com/token", data={
            "code": code, "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": redirect_uri, "grant_type": "authorization_code",
        })
    tokens = token_res.json()
    id_token = tokens.get("id_token", "")
    if not id_token:
        return RedirectResponse("/login?error=no_token")
    parts = id_token.split(".")
    if len(parts) < 2:
        return RedirectResponse("/login?error=bad_token")
    data = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    email = data.get("email", "")
    if not email.endswith(f"@{ALLOWED_DOMAIN}"):
        return RedirectResponse("/login?error=domain")
    token = _make_token(email)
    resp = RedirectResponse("/")
    resp.set_cookie("session", token, httponly=True, max_age=86400 * 30, samesite="lax")
    return resp

@app.post("/api/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("session")
    return resp

@app.get("/api/me")
async def me(session: str = Cookie(default="")):
    email = _verify_token(session)
    if not email:
        return JSONResponse({"username": None})
    return {"username": email.split("@")[0]}

# ─── 상태 ────────────────────────────────────────────────────────────────────
@app.get("/api/status")
async def status():
    return {"ai": ai_available, "notion": bool(NOTION_KEY and NOTION_DB_ID), "products": len(_notion_cache)}

# ─── AI 이미지 분석 → 상품명 추천 ────────────────────────────────────────────
@app.post("/api/analyze")
async def analyze_image(file: UploadFile = File(...), email: str = Depends(_require_auth)):
    if not ai_available:
        raise HTTPException(400, "AI API 키가 설정되지 않았습니다")
    await _ensure_notion_cache()
    img_bytes = await file.read()
    mime = file.content_type or "image/jpeg"
    existing_names = [p["name"] for p in _notion_cache]
    existing_str = ", ".join(n for n in existing_names[:200] if n and "(" not in n)

    prompt = f"""이 아동복 샘플 사진을 분석해 JSON만 반환하세요 (다른 텍스트 없이).

오즈키즈 상품명 규칙:
- 형식: "[대분류]-[감성합성어]"  예) 하의-메리리본 / 상의-홀리프릴 / 아우터-캔디튤
- 대분류: 상의/하의/아우터/원피스/슈즈/세트 중 하나
- 감성합성어: 테마/감성어 + 소재·장식·실루엣 합성어 (색상 단어 금지)
- 이미 사용 중인 상품명과 중복 금지

사용 중인 상품명: {existing_str}

반환 형식:
{{
  "suggested_names": ["하의-메리리본","상의-홀리프릴","아우터-캔디튤","하의-루돌프벨","상의-트윙클리본"],
  "category": "하의",
  "description": "제품 특징 한국어 1문장"
}}"""

    try:
        b64 = base64.b64encode(img_bytes).decode()
        if hasattr(gemini_client, 'models'):
            from google.genai import types as gtypes
            resp = gemini_client.models.generate_content(
                model="gemini-2.0-flash",
                contents=[gtypes.Part.from_bytes(data=img_bytes, mime_type=mime), prompt]
            )
            text = resp.text
        else:
            import google.generativeai as genai
            resp = gemini_client.generate_content([{"mime_type": mime, "data": b64}, prompt])
            text = resp.text

        import re
        m = re.search(r'\{.*\}', text, re.DOTALL)
        result = json.loads(m.group()) if m else {"suggested_names": [], "category": "", "description": ""}
        result["existing_count"] = len(existing_names)
        return result
    except Exception as e:
        raise HTTPException(500, f"AI 분석 실패: {str(e)}")

# ─── 노션 제품명 검색 ─────────────────────────────────────────────────────────
@app.get("/api/notion-search")
async def notion_search(q: str = "", email: str = Depends(_require_auth)):
    await _ensure_notion_cache()
    if not q:
        return {"results": []}
    q_lower = q.lower()
    matched = [p for p in _notion_cache if q_lower in p["name"].lower()][:20]
    return {"results": matched}

# ─── 노션 제품명 변경 ─────────────────────────────────────────────────────────
@app.post("/api/update-notion-name")
async def update_notion_name(body: dict, email: str = Depends(_require_auth)):
    page_id = body.get("page_id", "")
    new_name = body.get("new_name", "")
    if not page_id or not new_name:
        raise HTTPException(400, "page_id와 new_name 필요")
    if not NOTION_KEY:
        raise HTTPException(500, "Notion API 키 없음")
    payload = {"properties": {NOTION_NAME_PROP: {"title": [{"text": {"content": new_name}}]}}}
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.patch(
            f"https://api.notion.com/v1/pages/{page_id}",
            headers=NOTION_HEADERS, json=payload
        )
    if r.status_code != 200:
        raise HTTPException(500, f"노션 업데이트 실패: {r.text}")
    for p in _notion_cache:
        if p["page_id"] == page_id:
            p["name"] = new_name
            break
    return {"success": True, "new_name": new_name}

# ─── 제품컷 변환 (배경 제거) ─────────────────────────────────────────────────
@app.post("/api/product-shot")
async def product_shot(
    file: UploadFile = File(...),
    bg_color: str = "white",
    email: str = Depends(_require_auth),
):
    try:
        from rembg import remove
        from PIL import Image, ImageEnhance
    except ImportError:
        raise HTTPException(500, "rembg / Pillow 미설치")

    data = await file.read()
    try:
        src = Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception:
        raise HTTPException(400, "이미지를 읽을 수 없습니다")

    removed = remove(src)

    if bg_color == "transparent":
        result_img = removed
        fmt, mime, ext = "PNG", "image/png", "png"
    else:
        bg_rgb = (255, 255, 255) if bg_color == "white" else (240, 240, 240)
        bg = Image.new("RGBA", removed.size, bg_rgb + (255,))
        bg.paste(removed, mask=removed.split()[3])
        result_img = bg.convert("RGB")
        fmt, mime, ext = "JPEG", "image/jpeg", "jpg"

    result_img = ImageEnhance.Sharpness(result_img).enhance(1.15)
    buf = io.BytesIO()
    if fmt == "JPEG":
        result_img.save(buf, format="JPEG", quality=95, optimize=True)
    else:
        result_img.save(buf, format="PNG", optimize=True)
    buf.seek(0)

    fname = f"product_shot_{int(time.time())}.{ext}"
    return StreamingResponse(buf, media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'})
