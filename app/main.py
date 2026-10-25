import re
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from app.database import init_db, get_scan, get_findings
from app.models import ScanRequest, ScanResponse, ScanDetails, FindingOut
from app.scoring import get_security_level
from app.services.scanner import ScannerService
from app.config import OUTPUT_DIR

# The target is passed to external command-line tools (nmap, nikto, ...),
# so we only accept a plain http(s) URL or a bare host. This prevents a value
# such as "-iL /etc/passwd" from being interpreted as a tool option.
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


def validate_target(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Cible manquante.")
    candidate = url if "://" in url else "http://" + url
    host = urlparse(candidate).hostname or ""
    if not host or not HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="Cible invalide. Entrez une URL ou un nom d'hôte valide.")
    return url

app = FastAPI(title="WebScanner Python Complete", version="1.1")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
scanner = ScannerService()

@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
def home():
    return FileResponse("app/static/index.html")

@app.post("/api/webscan", response_model=ScanResponse)
def start_scan(payload: ScanRequest):
    if not payload.authorized:
        raise HTTPException(status_code=400, detail="Vous devez confirmer que vous êtes autorisé à scanner cette cible.")
    if payload.target_mode == "manual" and not payload.target_type:
        raise HTTPException(status_code=400, detail="En mode manuel, vous devez choisir un type de cible.")
    target = validate_target(payload.url)
    scan_id = scanner.enqueue(target, payload.mode, payload.authorized, payload.target_mode, payload.target_type)
    return ScanResponse(scan_id=scan_id, status="queued")

@app.get("/api/webscan/{scan_id}", response_model=ScanDetails)
def scan_details(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = [FindingOut(**{k: v for k, v in f.items() if k in {"id","asset","tool","severity","title","description"}}) for f in get_findings(scan_id)]
    score = scan.get("score")
    return ScanDetails(
        id=scan["id"],
        target=scan["target"],
        mode=scan["mode"],
        status=scan["status"],
        score=score,
        security_level=get_security_level(score) if score is not None else None,
        start_time=scan["start_time"],
        end_time=scan["end_time"],
        findings=findings,
        extra={
            "target_type": scan.get("target_type"),
            "selection_mode": scan.get("selection_mode"),
            "requested_target_type": scan.get("requested_target_type"),
            "authorization_confirmed": bool(scan.get("authorization_confirmed")),
        }
    )

@app.get("/api/webscan/{scan_id}/report")
def report(scan_id: str):
    path = OUTPUT_DIR / scan_id / "report.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path)

@app.get("/api/webscan/{scan_id}/report/pdf")
def report_pdf(scan_id: str):
    path = OUTPUT_DIR / scan_id / "report.pdf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="PDF report not found")
    return FileResponse(path, media_type="application/pdf", filename=f"{scan_id}_audit_report.pdf")
