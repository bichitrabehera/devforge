"""FastAPI wrapper around the existing Track 4 engine.

Run from the server/ directory:

    uvicorn main:app --reload --port 8000

All authorization, cryptography, revocation, recovery, audit and detection
decisions are delegated to the existing engine in src/ and services/.
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

try:  # package import (tests)
    from . import engine as engine_adapter
    from .engine import EngineError, error_reason
    from .routes import router
except ImportError:  # `uvicorn main:app` from inside server/
    import engine as engine_adapter  # type: ignore[no-redef]
    from engine import EngineError, error_reason  # type: ignore[no-redef]
    from routes import router  # type: ignore[no-redef]

app = FastAPI(title="Track 4 operator API", docs_url=None, redoc_url=None)


@app.middleware("http")
async def reset_request_context(request: Request, call_next):
    engine_adapter.reset_context()
    return await call_next(request)

# The operator console is the only allowed browser origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=False,
)

_STATUS = {
    "unauthorized": 401,
    "revoked": 403,
    "key_expired": 401,
    "invalid_message": 400,
    "backup_corrupt": 400,
    "log_tampered": 400,
    "invalid_request": 400,
}


def _safe(category: str, status_code: int, identity: str = "unknown",
          device: str = "unknown") -> JSONResponse:
    # Never echo exception text, tracebacks, paths, keys or configuration.
    # Every caller still receives the stable decision envelope.
    return JSONResponse(status_code=status_code, content={
        "error": category,
        "decision": "deny",
        "reason": error_reason(category),
        "identity": identity,
        "device": device,
    })


@app.exception_handler(EngineError)
async def engine_error_handler(_: Request, exc: EngineError):
    return _safe(exc.category, _STATUS.get(exc.category, 400),
                 exc.identity, exc.device)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_: Request, __: RequestValidationError):
    return _safe("invalid_request", 400)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(_: Request, exc: StarletteHTTPException):
    if exc.status_code in (404, 405):
        return _safe("invalid_request", exc.status_code)
    return _safe("invalid_request", 400)


@app.exception_handler(Exception)
async def unexpected_error_handler(_: Request, __: Exception):
    return _safe("invalid_request", 400)


app.include_router(router)


@app.get("/api/health")
@app.get("/health")
def health():
    return {"status": "ok", "service": "track4-api"}
