from __future__ import annotations

import hmac
import os
import re
import resource
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

APP_ROOT = Path(__file__).resolve().parent
TOKEN = os.environ.get("DASHBOARD_TOKEN", "")
BUILDS_ENABLED = os.environ.get("ENABLE_BUILDS", "false").lower() == "true"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
JOB_TTL_SECONDS = 15 * 60
BUILD_TIMEOUT_SECONDS = 300
ALLOWED_REGISTRIES = {"docker.io", "ghcr.io", "quay.io", "registry.k8s.io", "public.ecr.aws"}

app = FastAPI(title="OCI2BIN Web Dashboard", docs_url=None, redoc_url=None)
_jobs: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_active_build = False
_rate: dict[str, list[float]] = {}

class BuildRequest(BaseModel):
    image: str = Field(min_length=1, max_length=300)

def _authorize(authorization: str | None) -> None:
    if not TOKEN or len(TOKEN) < 24:
        raise HTTPException(503, "Dashboard is not configured. Set DASHBOARD_TOKEN to a random secret of at least 24 characters.")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Enter the dashboard access token.")
    supplied = authorization[7:]
    if not hmac.compare_digest(supplied, TOKEN):
        raise HTTPException(403, "Invalid dashboard access token.")

def _validate_image(value: str) -> str:
    image = value.strip()
    if not image or len(image) > 300 or any(c.isspace() for c in image):
        raise HTTPException(400, "Enter a valid public container image reference.")
    if "://" in image or image.startswith(("/", ".")) or ".." in image or "@" in image and not re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", image):
        raise HTTPException(400, "Invalid image reference. Use a tag or a SHA-256 digest.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]*", image):
        raise HTTPException(400, "Image reference contains unsupported characters.")
    # A registry can only be identified in the first path component when the
    # image contains a slash. Otherwise, e.g. "alpine:latest", the colon is a
    # tag separator and the image is a Docker Hub short name.
    if "/" in image:
        first = image.split("/", 1)[0]
        if "." in first or ":" in first or first.lower() == "localhost":
            if first.lower() not in ALLOWED_REGISTRIES:
                raise HTTPException(400, "For safety, only supported public registries are allowed: Docker Hub, GHCR, Quay, Kubernetes Registry, and Public ECR.")
    return image

def _limits() -> None:
    # Limits apply to the builder process and its children on Linux.
    resource.setrlimit(resource.RLIMIT_CPU, (BUILD_TIMEOUT_SECONDS, BUILD_TIMEOUT_SECONDS + 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARTIFACT_BYTES, MAX_ARTIFACT_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))

def _cleanup_expired() -> None:
    now = time.time()
    expired = []
    with _lock:
        for job_id, job in list(_jobs.items()):
            if job["created"] + JOB_TTL_SECONDS < now and job["status"] != "running":
                expired.append(job_id)
                _jobs.pop(job_id, None)
    for job_id in expired:
        job_dir = APP_ROOT / ".oci2bin-jobs" / job_id
        shutil.rmtree(job_dir, ignore_errors=True)

def _run_job(job_id: str, image: str) -> None:
    global _active_build
    job_dir = APP_ROOT / ".oci2bin-jobs" / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    output = job_dir / "artifact.bin"
    log_path = job_dir / "build.log"
    try:
        with open(log_path, "w", encoding="utf-8") as log:
            result = subprocess.run(
                ["oci2bin", "--pull-with", "skopeo", image, str(output)],
                cwd=job_dir,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=BUILD_TIMEOUT_SECONDS,
                check=False,
                close_fds=True,
                preexec_fn=_limits,
                env={
                    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                    "HOME": str(job_dir),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "OCI2BIN_INVOKED_AS": "oci2bin",
                },
            )
        if result.returncode != 0:
            detail = log_path.read_text(encoding="utf-8", errors="replace")[-6000:]
            with _lock:
                _jobs[job_id].update(status="failed", message="Build failed. See log output.", log=detail)
        elif not output.is_file():
            with _lock:
                _jobs[job_id].update(status="failed", message="Builder finished without producing an artifact.")
        elif output.stat().st_size > MAX_ARTIFACT_BYTES:
            output.unlink(missing_ok=True)
            with _lock:
                _jobs[job_id].update(status="failed", message="Artifact exceeded the 512 MiB size limit.")
        else:
            with _lock:
                _jobs[job_id].update(status="complete", message="Build completed.", size=output.stat().st_size)
    except subprocess.TimeoutExpired:
        with _lock:
            _jobs[job_id].update(status="failed", message="Build timed out after five minutes.")
    except Exception:
        with _lock:
            _jobs[job_id].update(status="failed", message="Build failed due to a server-side error. Check server logs.")
    finally:
        with _lock:
            _active_build = False

@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return PAGE

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/api/config")
def config() -> dict[str, bool]:
    return {"builds_enabled": BUILDS_ENABLED, "token_configured": bool(TOKEN and len(TOKEN) >= 24)}

@app.post("/api/builds")
def create_build(payload: BuildRequest, request: Request, authorization: str | None = Header(default=None)) -> dict[str, str]:
    global _active_build
    _authorize(authorization)
    if not BUILDS_ENABLED:
        raise HTTPException(503, "Online builds are disabled. Set ENABLE_BUILDS=true only after reviewing the security notes.")
    image = _validate_image(payload.image)
    _cleanup_expired()
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    with _lock:
        history = [t for t in _rate.get(client_ip, []) if now - t < 600]
        if len(history) >= 3:
            raise HTTPException(429, "Build limit reached. Try again in ten minutes.")
        if _active_build:
            raise HTTPException(429, "Another build is running. Please wait for it to finish.")
        history.append(now)
        _rate[client_ip] = history
        _active_build = True
        job_id = uuid.uuid4().hex
        _jobs[job_id] = {"created": now, "status": "running", "message": "Pulling image and building the executable.", "image": image}
    threading.Thread(target=_run_job, args=(job_id, image), daemon=True).start()
    return {"id": job_id, "status": "running"}

@app.get("/api/builds/{job_id}")
def build_status(job_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _authorize(authorization)
    _cleanup_expired()
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(404, "Build not found or expired.")
        result = {key: value for key, value in job.items() if key not in {"created", "image"}}
        result["download_url"] = f"/api/builds/{job_id}/download" if job["status"] == "complete" else None
        return result

@app.get("/api/builds/{job_id}/download")
def download_build(job_id: str, authorization: str | None = Header(default=None)) -> FileResponse:
    _authorize(authorization)
    with _lock:
        job = _jobs.get(job_id)
        if not job or job["status"] != "complete":
            raise HTTPException(404, "Completed artifact not found or expired.")
    path = APP_ROOT / ".oci2bin-jobs" / job_id / "artifact.bin"
    if not path.is_file():
        raise HTTPException(404, "Artifact has expired.")
    return FileResponse(path, media_type="application/octet-stream", filename="oci2bin-artifact.bin")

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0b1020">
<title>OCI2BIN Studio</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--line:#273451;--text:#eef3ff;--muted:#9aabc8;--blue:#76a9ff;--green:#80e1b0}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#172649,var(--bg) 55%);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}
main{max-width:900px;margin:auto;padding:32px 18px 60px}.brand{display:flex;gap:14px;align-items:center;margin-bottom:28px}.logo{width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,#77aaff,#9a83ff);display:grid;place-items:center;color:#091225;font-size:24px;font-weight:900}.eyebrow{color:var(--blue);font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}.brand h1{font-size:24px;margin:0}.brand p{margin:0;color:var(--muted);font-size:14px}
.panel{background:#111a2beF;border:1px solid var(--line);border-radius:20px;padding:24px;margin:16px 0;box-shadow:0 18px 60px #0002}.panel h2{font-size:19px;margin:0 0 6px}.muted{color:var(--muted)}label{display:block;font-size:14px;margin:16px 0 7px;color:#c9d7f0}input{width:100%;background:#0a1020;border:1px solid #344565;border-radius:10px;padding:13px 14px;color:var(--text);font:inherit;outline:none}input:focus{border-color:var(--blue)}.row{display:flex;gap:10px}.row input{flex:1;min-width:0}button,.download{border:0;border-radius:10px;padding:12px 18px;font:inherit;font-weight:750;background:var(--blue);color:#071326;cursor:pointer;text-decoration:none;display:inline-block}button:disabled{opacity:.5;cursor:wait}.note{background:#0a1224;border:1px solid var(--line);padding:13px 15px;border-radius:12px;color:var(--muted);font-size:13px;margin-top:15px}.status{margin-top:16px;padding:14px;border-radius:12px;background:#0a1224;border:1px solid var(--line);overflow-wrap:anywhere}.status strong{display:block;margin-bottom:4px}.ok{color:var(--green)}.bad{color:#ff9eae}code{color:#c7d7ff}ul{padding-left:20px;color:var(--muted)}li{margin:5px 0}.foot{text-align:center;color:#7889a8;font-size:12px;margin-top:25px}@media(max-width:560px){main{padding:22px 13px}.panel{padding:18px}.row{flex-direction:column}.row button{width:100%}}
</style></head>
<body><main>
<header class="brand"><div class="logo">O</div><div><div class="eyebrow">Build workspace</div><h1>OCI2BIN Studio</h1><p>Package a public container image as a Linux executable</p></div></header>
<section class="panel"><h2>Start a build</h2><p class="muted">Enter a public image name, tag, or SHA-256 digest. Example: <code>alpine:latest</code></p>
<label for="token">Dashboard access token</label><input id="token" type="password" autocomplete="off" placeholder="Paste the token configured by the owner">
<label for="image">Container image</label><input id="image" value="alpine:latest" maxlength="300" placeholder="alpine:latest">
<div class="row" style="margin-top:14px"><button id="build">Build executable</button><button id="clear" style="background:#263550;color:#eef3ff">Clear status</button></div>
<div id="status" class="status" role="status" aria-live="polite">Ready when the server is configured.</div>
<div class="note">Security: this dashboard packages images but does not run the resulting executable. Builds are limited to allowlisted public registries, one build at a time, three starts per IP per ten minutes, a five-minute timeout, and a 512 MiB output cap. This is still a hobby deployment, not a hardened multi-user build service.</div>
</section>
<section class="panel"><h2>How it works</h2><ul><li>Fetches an image using Skopeo without requiring a Docker daemon.</li><li>Creates an executable artifact with the OCI2BIN CLI.</li><li>Provides a temporary download link for completed builds.</li><li>Build records and artifacts expire after 15 minutes and are lost when the service restarts.</li></ul><p class="muted">Only build images you trust. Do not enter credentials, private registry tokens, or secrets.</p></section>
<div class="foot">OCI2BIN Studio · Linux artifacts only</div></main>
<script>
const tokenEl=document.getElementById('token'), imageEl=document.getElementById('image'), statusEl=document.getElementById('status'), buildBtn=document.getElementById('build');
let active=false;
function show(title,detail='',kind=''){statusEl.innerHTML='';const strong=document.createElement('strong');strong.textContent=title;strong.className=kind;statusEl.append(strong);const p=document.createElement('div');p.textContent=detail;statusEl.append(p)}
async function api(path,options={}){const token=tokenEl.value.trim();return fetch(path,{...options,headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json',...(options.headers||{})}})}
async function poll(id){for(let i=0;i<120;i++){await new Promise(r=>setTimeout(r,2500));let res=await api('/api/builds/'+id);let data=await res.json();if(!res.ok){show('Could not read build status',data.detail||'Request failed','bad');return}if(data.status==='complete'){show('Build complete','Artifact size: '+Math.round((data.size||0)/1024/1024*10)/10+' MiB. Preparing download…','ok');const res2=await api('/api/builds/'+id+'/download');if(!res2.ok){const e=await res2.json().catch(()=>({}));show('Download unavailable',e.detail||'The artifact may have expired.','bad');return}const blob=await res2.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='oci2bin-artifact.bin';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);show('Build complete','Your executable download should begin now. Artifacts expire after 15 minutes.','ok');return}if(data.status==='failed'){show('Build failed',data.message+(data.log?'\n\n'+data.log:''),'bad');return}show('Build in progress',data.message||'Pulling image and packaging it…')}show('Still processing','The build is taking longer than expected. Refresh and check the service logs if it does not finish.')}
buildBtn.addEventListener('click',async()=>{if(active)return;active=true;buildBtn.disabled=true;try{show('Starting build','Validating image and queueing a job…');const res=await api('/api/builds',{method:'POST',body:JSON.stringify({image:imageEl.value})});const data=await res.json();if(!res.ok){show('Could not start build',data.detail||'Request failed','bad');return}await poll(data.id)}catch(e){show('Connection error','Could not reach the server. Check the deployment and try again.','bad')}finally{active=false;buildBtn.disabled=false}});
document.getElementById('clear').addEventListener('click',()=>show('Ready','Enter an image reference to start a new build.'));
fetch('/api/config').then(r=>r.json()).then(c=>{if(!c.builds_enabled)show('Builds are disabled','The server owner must set ENABLE_BUILDS=true after reviewing the security notes.','bad');else if(!c.token_configured)show('Server needs configuration','Set DASHBOARD_TOKEN to a random secret of at least 24 characters.','bad');else show('Ready','Enter your dashboard token and a public image reference.','ok')}).catch(()=>show('Server not reachable','Check the deployment.','bad'));
</script></body></html>
"""
