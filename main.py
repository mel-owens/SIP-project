from fastapi import FastAPI 
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router
from app.database import Base, engine
from app.admin import init_admin
from app.database import engine
import base64
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from app.routes import router
from app.database import Base, engine
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app import models
import json
from starlette.middleware.base import BaseHTTPMiddleware
from app.database import get_db
from sqlalchemy.orm import Session
from sqladmin import Admin, ModelView
from app.models import Email, AuditLog
import time
from starlette.requests import Request
from starlette.responses import Response
from app.database import SessionLocal, engine
from app.models import AuditLog  # id, method, path, status, duration_ms, ip, ts
from fastapi.routing import APIRoute
from sqlalchemy import text
import secrets, time
from collections import defaultdict, deque
from app import routes   # has: router with /analyze-email, etc.

# fallback
try:
    from app import __version__  # e.g., "0.4.0"
except Exception:
    __version__ = "0.0.0-dev"

app = FastAPI(
    title="Tailored Learning API",
    description="Local-only email analysis and training API.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
    )
templates = Jinja2Templates(directory="app/templates")

# audit looging 
@app.middleware("http")
async def audit_mw(request: Request, call_next):
    start = time.perf_counter()
    ip = request.client.host if request.client else "unknown"
    try:
        response: Response = await call_next(request)
        status = response.status_code
        return response
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)
        db: Session = SessionLocal()
        try:
            log = AuditLog(
                method=request.method,
                path=str(request.url.path),
                status=status,
                duration_ms=duration_ms,
                ip=ip,
            )
            db.add(log)
            db.commit()
        finally:
            db.close()


#  app factory with unique operation IDs 
def generate_unique_id(route: APIRoute):
    # tag-name if present; else route.name is function name
    base = f"{route.tags[0]}-" if route.tags else ""
    return f"{base}{route.name}"

app = FastAPI(generate_unique_id_function=generate_unique_id, 
              title="Email Security Plugin")

# CORS: allow your frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173","http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# basic Auth middleware just for /admin 
ADMIN_USER = "admin"
ADMIN_PASS = "changeme"  # TODO: read from environment in production

@app.middleware("http")
async def basic_auth_admin_only(request: Request, call_next):
    # only protect SQLAdmin UI
    if request.url.path.startswith("/admin"):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Basic "):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="admin"'},
            )
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="admin"'},
            )
        if not (username == ADMIN_USER and password == ADMIN_PASS):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="admin"'},
            )
    return await call_next(request)
# -------------------------------------------------------

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    init_admin(app, engine)   # mounts /admin
    app.include_router(router)

app.include_router(router)

@app.get("/")
def root():
    return {"message": "Tailored Learning API Running"}

@app.get("/recent")
def recent():
    return {"items":[
        {"id":"e1","sender":"support@contoso.com","subject":
         "Invoice available","verdict":"Legitimate","risk":10},
        {"id":"e2","sender":"it-help@corp-reset.com","subject":
         "URGENT password reset","verdict":"Phishing","risk":85},
    ]}

@app.get("/status", response_class=HTMLResponse)
def status_page(request: Request, db: Session = Depends(get_db)):
    # DB health
    try:
        db.execute("SELECT 1")
        db_health = "ok"
    except Exception:
        db_health = "down"

    # counts
    emails = db.query(models.Email).count()
    urls = db.query(models.Url).count()
    audits = db.query(models.AuditLog).count()

    recent = db.query(models.Email).order_by
    (models.Email.created_at.desc()).limit(10).all()

    return templates.TemplateResponse(
        "status.html",
        {
            "request": request,
            "health": {"api": "ok", "db": db_health},
            "version": "0.1.0",
            "counts": {"emails": emails, "urls": urls, "audits": audits},
            "recent": recent,
        },
    )



class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        # log only POSTs to analyze
        if request.method == "POST" and request.url.path.startswith("/analyze-email"):
            try:
                db: Session = next(get_db())
                db.add(AuditLog(action="HTTP_ANALYZE", detail=json.dumps({
                    "path": str(request.url.path),
                    "status": response.status_code
                })))
                db.commit()
            except Exception:
                pass
        return response 
app.add_middleware(AuditMiddleware)

# Request size limit (1 MB) 
class LimitBodySizeMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_body_size: int):
        super().__init__(app)
        self.max_body_size = max_body_size

    async def dispatch(self, request: Request, call_next):
        # Only buffer bodies for methods that usually have one; adjust if needed
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > self.max_body_size:
                raise HTTPException(status_code=413, detail="Payload too large")
            # Re-inject body for downstream handlers
            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}
            request._receive = receive
        return await call_next(request)

app.add_middleware(LimitBodySizeMiddleware, max_body_size=1_000_000)


# Simple IP allowlist 
ALLOWLIST = {"127.0.0.1"}  # load from env/config for real use

@app.middleware("http")
async def ip_allowlist(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    if ip not in ALLOWLIST:
        # Allow healthz and docs unauthenticated from localhost only
        if request.url.path not in ("/healthz", "/docs", "/openapi.json"):
            raise HTTPException(status_code=403, detail="Forbidden")
    return await call_next(request)

# Tiny in-memory rate limiter for /analyze-email 
WINDOW_SEC = 60
MAX_REQ = 20
_hits = defaultdict(lambda: deque())

def _allow(ip: str) -> bool:
    q = _hits[ip]
    now = time.time()
    while q and now - q[0] > WINDOW_SEC:
        q.popleft()
    if len(q) >= MAX_REQ:
        return False
    q.append(now)
    return True

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path.startswith("/analyze-email"):
        ip = request.client.host if request.client else "unknown"
        if not _allow(ip):
            raise HTTPException(status_code=429, detail="Too many requests")
    return await call_next(request)

#  Audit logging (global) 
@app.middleware("http")
async def audit_logging(request: Request, call_next):
    start = time.perf_counter()
    ip = request.client.host if request.client else "unknown"
    status_code = 500
    try:
        response: Response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)
        db: Session = SessionLocal()
        try:
            db.add(AuditLog(
                method=request.method,
                path=str(request.url.path),
                status=status_code,
                duration_ms=duration_ms,
                ip=ip,
            ))
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

#  Health check 
from fastapi import APIRouter
health = APIRouter()

@health.get("/healthz", tags=["system"], operation_id="system-health")
def healthz():
    db_ok = False
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    finally:
        db.close()
    return {"ok": True, "version": __version__, "db": db_ok}

app.include_router(health)

#  Admin UI (SQLAdmin) with HTTP Basic guard 
from sqladmin import Admin, ModelView
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic()
ADMIN_USER = "admin"
ADMIN_PASS = "change_me"  # TODO: load from env

def require_admin(credentials: HTTPBasicCredentials = Depends(security)):
    u_ok = secrets.compare_digest(credentials.username, ADMIN_USER)
    p_ok = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (u_ok and p_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Basic"},
        )
    return True

admin = Admin(app, engine)

class EmailAdmin(ModelView, model=Email):
    name = "Emails"
    category = "Data"
    column_searchable_list = [Email.sender, Email.subject]
    column_sortable_list = [Email.created_at]


class AuditLogAdmin(ModelView, model=AuditLog):
    name = "Audit Logs"
    category = "System"
     
    column_list = [
        AuditLog.id,
        AuditLog.created_at,  
        AuditLog.action,
        AuditLog.email_id,
        AuditLog.detail,
    ]
    column_sortable_list = [AuditLog.ts, AuditLog.status, AuditLog.duration_ms]
    column_default_sort = [(AuditLog.created_at, True)]  # True = DESC


admin.add_view(EmailAdmin)
admin.add_view(AuditLogAdmin)

# Protect the admin mount path with Basic auth by adding a tiny guard endpoint
async def guard_admin(request: Request, call_next):
    if request.url.path.startswith("/admin"):
        # Trigger HTTP Basic flow
        auth = request.headers.get("authorization") or ""
        if not auth.startswith("Basic "):
            # Force browser prompt
            return Response(status_code=401, headers={"WWW-Authenticate": "Basic"})
        # Let FastAPI validate creds using the dependency for uniformity
        try:
            # Reuse the dependency’s logic
            from base64 import b64decode
            user, pwd = b64decode(auth.split(" ", 1)[1]).decode().split(":", 1)
            require_admin(HTTPBasicCredentials(username=user, password=pwd))
        except Exception:
            return Response(status_code=401, headers={"WWW-Authenticate": "Basic"})
    return await call_next(request)


app.include_router(routes.router)