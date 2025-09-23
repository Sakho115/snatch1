# snatch_backend.py
"""
SNATCH – universal downloader backend (single-file, FastAPI)
Latest fixed version:
- Auto-detect ffmpeg and pass its location to yt-dlp.
- If ffmpeg missing, yt-dlp will avoid merging formats (retry fallback).
- Sanitizes filenames to ASCII-safe values (prevents latin-1 header errors).
- Uses yt-dlp options to restrict filenames and behave politely.
- Supports direct downloads + yt-dlp (YouTube, Instagram, TikTok, etc).
- Keeps in-memory JOB registry, TTL janitor, SSRF guards, and size limits.
"""

import asyncio
import contextlib
import ipaddress
import mimetypes
import os
import re
import shutil
import socket
import time
import unicodedata
import uuid
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, AnyHttpUrl
import uvicorn

# optional yt-dlp
with contextlib.suppress(Exception):
    import yt_dlp  # type: ignore

# -------------------- Config --------------------
MAX_SIZE_MB = int(os.getenv("MAX_SIZE_MB", "512"))
MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024
TTL_SECONDS = int(os.getenv("TTL_SECONDS", "3600"))
ALLOW_YTDLP = os.getenv("ALLOW_YTDLP", "1") not in ("0", "false", "False")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
COOKIES_FILE = os.getenv("COOKIES_FILE", "").strip() or None

HOME = Path.home()
DOWNLOADS_ROOT = Path(os.getenv("SNATCH_DIR") or (HOME / "Downloads" / "snatch"))
DOWNLOADS_ROOT.mkdir(parents=True, exist_ok=True)
TMP_ROOT = DOWNLOADS_ROOT

app = FastAPI(title="Snatch Backend", version="2.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if CORS_ORIGINS == ["*"] else CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Models --------------------
class DownloadRequest(BaseModel):
    url: AnyHttpUrl
    filename: Optional[str] = None

class VideoRequest(BaseModel):
    url: AnyHttpUrl
    format: Optional[str] = None
    audio_only: Optional[bool] = False

class UnifiedRequest(BaseModel):
    url: AnyHttpUrl
    filename: Optional[str] = None
    format: Optional[str] = None
    audio_only: Optional[bool] = False

class ProbeRequest(BaseModel):
    url: AnyHttpUrl

class Job(BaseModel):
    id: str
    kind: str
    url: str
    filename: Optional[str] = None
    filepath: Optional[str] = None
    bytes_total: Optional[int] = None
    bytes_done: int = 0
    status: str = "queued"
    error: Optional[str] = None
    started_at: float = time.time()
    updated_at: float = time.time()
    expires_at: float = time.time() + TTL_SECONDS
    meta: Optional[Dict[str, Any]] = None

JOBS: Dict[str, Job] = {}

# -------------------- Helpers --------------------
PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]

BLOCKED_SCHEMES = {"file", "ftp", "gopher", "smb", "ssh", "ws", "wss"}

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0 Safari/537.36",
    "Accept": "*/*",
}

# sanitize filename to ASCII-safe header-friendly value
def sanitize_filename_for_header(name: str, fallback: str = "file") -> str:
    name = (name or "").strip() or fallback
    # Normalize and remove non-ascii
    name = unicodedata.normalize("NFKD", name)
    name = name.encode("ascii", "ignore").decode("ascii")
    # Keep only safe chars
    name = re.sub(r'[^A-Za-z0-9._-]+', '_', name).strip('_')
    if not name:
        name = fallback
    # limit length
    if len(name) > 200:
        name = name[:200]
    return name

async def resolve_remote_ip(host: str) -> str:
    if not host:
        raise HTTPException(400, detail="Invalid URL host")
    loop = asyncio.get_event_loop()
    infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ip = infos[0][4][0]
    ip_obj = ipaddress.ip_address(ip)
    for net in PRIVATE_NETS:
        if ip_obj in net:
            raise HTTPException(400, detail="Blocked internal IP range")
    return ip

def mk_job(kind: str, url: str, filename: Optional[str] = None) -> Job:
    jid = str(uuid.uuid4())
    jb = Job(id=jid, kind=kind, url=url, filename=filename)
    JOBS[jid] = jb
    return jb

def job_dir(job: Job) -> Path:
    d = TMP_ROOT / job.id
    d.mkdir(parents=True, exist_ok=True)
    return d

async def fetch_headers(client: httpx.AsyncClient, url: str) -> httpx.Response:
    try:
        r = await client.head(url, follow_redirects=True, timeout=20, headers=DEFAULT_HEADERS)
        if r.status_code >= 400 or r.headers.get("Content-Length") is None:
            r = await client.get(url, headers={**DEFAULT_HEADERS, "Range": "bytes=0-0"}, follow_redirects=True, timeout=20)
        return r
    except httpx.HTTPError as e:
        raise HTTPException(400, detail=f"HEAD/GET failed: {e}")

def guess_filename_from_url(u: str) -> str:
    path_part = Path(urlparse(u).path).name
    return path_part or "download"

def is_probably_video_site(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    for key in ("youtube.", "youtu.be", "instagram.", "tiktok.", "facebook.", "fb.", "twitter.", "x.com", "reddit.", "vimeo.", "dailymotion.", "twitch."):
        if key in host:
            return True
    return False

# -------------------- ffmpeg detection --------------------
def find_ffmpeg() -> Optional[str]:
    from shutil import which
    p = which("ffmpeg")
    if p:
        return p
    common = ["/usr/bin/ffmpeg", "/usr/local/bin/ffmpeg", "C:\\ffmpeg\\bin\\ffmpeg.exe"]
    for c in common:
        if Path(c).exists():
            return c
    return None

FFMPEG_PATH = find_ffmpeg()
if FFMPEG_PATH:
    print(f"[snatch] ffmpeg found at: {FFMPEG_PATH}")
else:
    print("[snatch] ffmpeg not found on PATH. yt-dlp will prefer 'best' single-file formats (no merging).")

# -------------------- yt-dlp helpers --------------------
def _make_ytdlp_opts(outdir: Path, fmt: Optional[str], audio_only: bool) -> Dict[str, Any]:
    template = str(outdir / "%(title).200B-%(id)s.%(ext)s")
    # If ffmpeg present allow merging, else prefer single-file 'best' to avoid merge requirement
    if FFMPEG_PATH:
        ytdlp_format = "bestaudio/best" if audio_only else (fmt or "bestvideo+bestaudio/best")
    else:
        ytdlp_format = "bestaudio/best" if audio_only else (fmt or "best")

    opts: Dict[str, Any] = {
        'outtmpl': template,
        'format': ytdlp_format,
        'noplaylist': True,
        'quiet': True,
        'concurrent_fragment_downloads': 4,
        'retries': 3,
        'nocheckcertificate': False,
        'http_headers': {'User-Agent': DEFAULT_HEADERS['User-Agent']},
        # ensure file names are limited / safe
        'restrictfilenames': True,
        'windowsfilenames': True,
    }

    if FFMPEG_PATH:
        # point to parent dir (yt-dlp accepts binary or dir; parent is safe)
        opts['ffmpeg_location'] = str(Path(FFMPEG_PATH).parent)
        opts['merge_output_format'] = 'mp4'

    if audio_only or (fmt and fmt.lower() in {"mp3", "m4a", "wav", "ogg", "flac"}):
        codec = (fmt or "mp3").lower()
        opts['format'] = 'bestaudio/best'
        opts['postprocessors'] = [{
            'key': 'FFmpegExtractAudio',
            'preferredcodec': codec,
            'preferredquality': '0',
        }]
    if COOKIES_FILE and Path(COOKIES_FILE).exists():
        opts['cookiefile'] = COOKIES_FILE
    return opts

def _pick_latest_file_in_dir(d: Path) -> Optional[Path]:
    try:
        files = [p for p in d.iterdir() if p.is_file()]
        if not files:
            return None
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return files[0]
    except Exception:
        return None

async def run_ytdlp(job: Job, fmt: Optional[str], audio_only: bool = False) -> None:
    if 'yt_dlp' not in globals() or not ALLOW_YTDLP:
        raise HTTPException(400, detail="yt-dlp not enabled on server")

    job.status = "running"
    job.started_at = time.time()
    job.updated_at = time.time()

    outdir = job_dir(job)
    opts = _make_ytdlp_opts(outdir, fmt, audio_only)

    def hook(d):
        if d.get('status') == 'downloading':
            total = d.get('total_bytes') or d.get('total_bytes_estimate')
            job.bytes_total = int(total) if total else None
            job.bytes_done = int(d.get('downloaded_bytes') or 0)
            job.updated_at = time.time()
        elif d.get('status') == 'finished':
            job.updated_at = time.time()

    opts['progress_hooks'] = [hook]

    info = None
    try:
        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(str(job.url), download=True)
    except Exception as e:
        err_text = str(e)
        print(f"[snatch] yt-dlp initial error: {err_text}")
        # retry logic: if merging error occurred and no ffmpeg, retry with 'best' single-file
        if ("requested merging of multiple formats" in err_text or "You have requested merging of multiple formats" in err_text) and not FFMPEG_PATH:
            print("[snatch] retrying yt-dlp with safe 'best' format (no merging) because ffmpeg not found")
            safe_opts = _make_ytdlp_opts(outdir, "best", audio_only)
            safe_opts['progress_hooks'] = [hook]
            try:
                with yt_dlp.YoutubeDL(safe_opts) as ydl2:
                    info = ydl2.extract_info(str(job.url), download=True)
            except Exception as e2:
                print(f"[snatch] yt-dlp retry failed: {e2}")
                raise HTTPException(400, detail=f"yt-dlp error: {e2}")
        else:
            raise HTTPException(400, detail=f"yt-dlp error: {e}")

    # finalize file path
    try:
        fpath = None
        if info and isinstance(info, dict):
            if 'requested_downloads' in info and info['requested_downloads']:
                fpath = info['requested_downloads'][0].get('filepath')
            else:
                # use ydl.prepare_filename via a short YDL (requires import)
                try:
                    with yt_dlp.YoutubeDL({'quiet': True}) as ytmp:
                        fpath = ytmp.prepare_filename(info)
                except Exception:
                    fpath = None

        if fpath:
            fpath = Path(fpath)
        else:
            # fallback: pick the newest file in outdir
            fpath = _pick_latest_file_in_dir(outdir)

        if not fpath or not fpath.exists():
            # try searching common extensions
            if fpath and fpath.parent.exists():
                for ext in ("mp4", "mkv", "webm", "m4a", "mp3", "wav", "ogg", "flac"):
                    candidate = fpath.with_suffix('.' + ext) if fpath else None
                    if candidate and candidate.exists():
                        fpath = candidate
                        break
            if not fpath or not fpath.exists():
                # final fallback: scan outdir
                fpath = _pick_latest_file_in_dir(outdir)
                if not fpath:
                    raise HTTPException(400, detail="yt-dlp finished but produced no file")

        # sanitize file name and (optionally) rename file to ASCII-safe name
        safe_name = sanitize_filename_for_header(fpath.name)
        if safe_name != fpath.name:
            try:
                new_path = fpath.with_name(safe_name)
                # avoid overwrite
                i = 1
                while new_path.exists():
                    stem = Path(safe_name).stem
                    suf = fpath.suffix
                    new_path = fpath.with_name(f"{stem}_{i}{suf}")
                    i += 1
                fpath = fpath.rename(new_path)
            except Exception as e:
                print(f"[snatch] warning: failed to rename {fpath} -> sanitized name: {e}")

        job.filepath = str(fpath)
        job.filename = fpath.name
        job.bytes_done = fpath.stat().st_size
        job.bytes_total = job.bytes_done
        job.meta = {
            "title": (info.get("title") if isinstance(info, dict) else None),
            "ext": (info.get("ext") if isinstance(info, dict) else None),
            "duration": (info.get("duration") if isinstance(info, dict) else None),
            "uploader": (info.get("uploader") if isinstance(info, dict) else None),
            "webpage_url": (info.get("webpage_url") if isinstance(info, dict) else None),
            "thumbnail": (info.get("thumbnail") if isinstance(info, dict) else None),
        }
        job.status = "done"
        job.updated_at = time.time()
        job.expires_at = time.time() + TTL_SECONDS
    except HTTPException:
        raise
    except Exception as e:
        print(f"[snatch] finalization error after yt-dlp: {e}")
        raise HTTPException(500, detail=f"Post-download error: {e}")

# -------------------- Direct downloader with HTML-detection & fallback ---------------
async def stream_download(job: Job) -> None:
    job.status = "running"
    job.started_at = time.time()
    job.updated_at = time.time()

    parsed = urlparse(str(job.url))
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(400, detail="Only http/https supported for direct download")
    if parsed.scheme in BLOCKED_SCHEMES:
        raise HTTPException(400, detail="Scheme blocked")

    await resolve_remote_ip(parsed.hostname or "")

    async with httpx.AsyncClient() as client:
        hdr = await fetch_headers(client, str(job.url))
        size_header = hdr.headers.get("Content-Length")
        try:
            size = int(size_header) if size_header else 0
        except Exception:
            size = 0
        if size and size > MAX_SIZE_BYTES:
            raise HTTPException(413, detail=f"File too large (>{MAX_SIZE_MB} MB)")
        job.bytes_total = size if size > 0 else None

        cd = hdr.headers.get("Content-Disposition", "") or ""
        suggested = None
        try:
            m = re.search(r"filename\*=UTF-8''([^;]+)", cd)
            if m:
                suggested = m.group(1)
            else:
                m2 = re.search(r'filename="?([^";]+)"?', cd)
                if m2:
                    suggested = m2.group(1)
        except Exception:
            suggested = None
        if not suggested:
            suggested = guess_filename_from_url(str(hdr.url or job.url))
        ext = Path(suggested).suffix
        base = job.filename or suggested
        if not Path(base).suffix and ext:
            base = base + ext

        # sanitize base for filesystem + header safety
        fname = sanitize_filename_for_header(base)

        dest_dir = job_dir(job)
        dest_path = dest_dir / fname

        headers = {**DEFAULT_HEADERS, "Referer": str(job.url)}
        async with client.stream("GET", str(job.url), follow_redirects=True, timeout=None, headers=headers) as resp:
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code, detail=f"Download failed: HTTP {resp.status_code}")

            content_type = resp.headers.get("Content-Type", "").lower()
            looks_like_html = "text/html" in content_type

            written = 0
            with open(dest_path, "wb") as f:
                async for chunk in resp.aiter_bytes(chunk_size=1024 * 64):
                    if chunk:
                        f.write(chunk)
                        written += len(chunk)
                        job.bytes_done = written
                        job.updated_at = time.time()
                        if not job.bytes_total and written > MAX_SIZE_BYTES:
                            raise HTTPException(413, detail=f"File exceeded limit (>{MAX_SIZE_MB} MB)")

            job.bytes_done = dest_path.stat().st_size
            job.bytes_total = job.bytes_done

        if looks_like_html:
            try:
                head = dest_path.read_bytes()[:2048].lower()
                if b"<html" in head or b"<!doctype html" in head or b"<script" in head:
                    if ALLOW_YTDLP and 'yt_dlp' in globals() and is_probably_video_site(job.url):
                        print("[snatch] direct fetch returned HTML -> falling back to yt-dlp")
                        with contextlib.suppress(Exception):
                            dest_path.unlink()
                        await run_ytdlp(job, None, audio_only=False)
                        return
                    else:
                        job.status = "error"
                        job.error = "Downloaded content appears to be an HTML page (not media). Try /api/video or enable yt-dlp."
                        job.updated_at = time.time()
                        return
            except Exception:
                pass

        job.filepath = str(dest_path)
        job.filename = dest_path.name
        job.status = "done"
        job.updated_at = time.time()
        job.expires_at = time.time() + TTL_SECONDS

# -------------------- Janitor --------------------
async def janitor_loop():
    while True:
        now = time.time()
        to_delete = []
        for jid, job in list(JOBS.items()):
            if job.expires_at < now or job.status in {"deleted"}:
                to_delete.append(jid)
        for jid in to_delete:
            job = JOBS.get(jid)
            if not job:
                continue
            d = TMP_ROOT / jid
            with contextlib.suppress(Exception):
                if d.exists():
                    shutil.rmtree(d)
            JOBS.pop(jid, None)
        await asyncio.sleep(30)

@app.on_event("startup")
async def _startup():
    print("[snatch] starting janitor loop...")
    asyncio.create_task(janitor_loop())

# -------------------- API Routes --------------------
@app.post("/api/download")
async def create_download(req: DownloadRequest):
    parsed = urlparse(str(req.url))
    if parsed.scheme in BLOCKED_SCHEMES:
        raise HTTPException(400, detail="Scheme not allowed")
    if not parsed.hostname:
        raise HTTPException(400, detail="Invalid URL")

    job = mk_job("direct", str(req.url), req.filename)

    async def runner():
        try:
            await stream_download(job)
        except HTTPException as he:
            job.status = "error"
            job.error = he.detail if isinstance(he.detail, str) else str(he.detail)
            job.updated_at = time.time()
        except Exception as e:
            job.status = "error"
            job.error = str(e)
            job.updated_at = time.time()

    asyncio.create_task(runner())
    return {"id": job.id}

@app.post("/api/video")
async def create_video(req: VideoRequest):
    if not ALLOW_YTDLP:
        raise HTTPException(400, detail="Video downloads disabled on server")
    job = mk_job("video", str(req.url))

    async def runner():
        try:
            await run_ytdlp(job, req.format, audio_only=bool(req.audio_only))
        except HTTPException as he:
            job.status = "error"
            job.error = he.detail if isinstance(he.detail, str) else str(he.detail)
            job.updated_at = time.time()
        except Exception as e:
            job.status = "error"
            job.error = str(e)
            job.updated_at = time.time()

    asyncio.create_task(runner())
    return {"id": job.id}

@app.post("/api/unified")
async def create_unified(req: UnifiedRequest):
    url = str(req.url)
    if is_probably_video_site(url) and ALLOW_YTDLP and 'yt_dlp' in globals():
        job = mk_job("video", url, req.filename)
        async def runner():
            try:
                await run_ytdlp(job, req.format, audio_only=bool(req.audio_only))
            except Exception as e:
                job.status = "error"
                job.error = str(e)
                job.updated_at = time.time()
        asyncio.create_task(runner())
    else:
        job = mk_job("direct", url, req.filename)
        async def runner():
            try:
                await stream_download(job)
            except Exception as e:
                job.status = "error"
                job.error = str(e)
                job.updated_at = time.time()
        asyncio.create_task(runner())
    return {"id": job.id}

@app.post("/api/probe")
async def api_probe(req: ProbeRequest):
    info = await probe_url(str(req.url))
    return info

async def probe_url(url: str):
    info = {"url": url}
    if 'yt_dlp' in globals() and ALLOW_YTDLP:
        try:
            with yt_dlp.YoutubeDL({'quiet': True, 'noplaylist': True, 'restrictfilenames': True}) as ydl:
                data = ydl.extract_info(url, download=False)
                info.update({
                    "type": "video",
                    "title": data.get("title"),
                    "duration": data.get("duration"),
                    "ext": data.get("ext"),
                    "thumbnail": data.get("thumbnail"),
                    "uploader": data.get("uploader"),
                    "webpage_url": data.get("webpage_url") or url,
                })
                return info
        except Exception as e:
            print(f"[snatch] probe: yt-dlp probe failed: {e}")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(400, detail="Unsupported scheme for probe")
    await resolve_remote_ip(parsed.hostname or "")
    async with httpx.AsyncClient() as client:
        r = await fetch_headers(client, url)
        info.update({
            "type": "file",
            "content_type": r.headers.get("Content-Type"),
            "content_length": r.headers.get("Content-Length"),
            "final_url": str(r.url),
        })
        return info

@app.get("/api/status/{jid}")
async def get_status(jid: str):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404, detail="Not found")
    return job.dict()

@app.get("/api/file/{jid}")
async def get_file(jid: str):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404, detail="Not found")
    if job.status != "done" or not job.filepath:
        raise HTTPException(409, detail="File not ready")
    path = Path(job.filepath)
    if not path.exists():
        raise HTTPException(410, detail="File expired")

    # ensure header-safe filename
    header_name = sanitize_filename_for_header(job.filename or path.name)

    # include custom headers (these are ASCII-safe)
    headers = {
        "X-Snatch-Id": job.id,
        "Cache-Control": "no-store"
    }

    mime, _ = mimetypes.guess_type(path.name)
    return FileResponse(
        path,
        media_type=mime or "application/octet-stream",
        filename=header_name,
        headers=headers
    )

@app.delete("/api/delete/{jid}")
async def delete_job(jid: str):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404, detail="Not found")
    job.status = "deleted"
    job.updated_at = time.time()
    job.expires_at = 0
    return {"ok": True}

# ---------- One-shot "smart" downloader that returns the file directly ----------
@app.post("/download")
async def download_file(request: Request):
    try:
        data = await request.json()
    except Exception as e:
        raise HTTPException(400, detail=f"Invalid JSON: {e}")

    url = str(data.get("url") or "").strip()
    if not url:
        raise HTTPException(400, detail="URL is required")
    fmt = data.get("format")
    audio_only = bool(data.get("audio_only") or False)

    try:
        if is_probably_video_site(url) and ALLOW_YTDLP and 'yt_dlp' in globals():
            job = mk_job("video", url)
            await run_ytdlp(job, fmt, audio_only=audio_only)
        else:
            job = mk_job("direct", url)
            await stream_download(job)
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"[snatch] download_file error: {e}")
        raise HTTPException(500, detail=f"Download failed: {e}")

    path = Path(job.filepath or "")
    if not path.exists():
        raise HTTPException(410, detail="Download failed or file expired")

    header_name = sanitize_filename_for_header(job.filename or path.name)
    mime, _ = mimetypes.guess_type(path.name)
    headers = {
        "X-Snatch-Id": job.id,
        "Cache-Control": "no-store"
    }
    return FileResponse(path, media_type=mime or "application/octet-stream", filename=header_name, headers=headers)

@app.get("/")
async def root():
    return JSONResponse({
        "name": "snatch-backend",
        "version": "2.3.0",
        "max_size_mb": MAX_SIZE_MB,
        "ttl_seconds": TTL_SECONDS,
        "allow_ytdlp": ALLOW_YTDLP,
        "cookies_file": bool(COOKIES_FILE),
        "download_root": str(TMP_ROOT),
        "ffmpeg": FFMPEG_PATH,
    })

if __name__ == "__main__":
    uvicorn.run("snatch:app", host="0.0.0.0", port=8000, reload=False)
