"""
MailTrace.AI - Core FastAPI Forensic Gateway
Enterprise Forensic Intelligence & Section 63 BSA 2023 Statutory Platform
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from backend.app.core.config import (
    PLATFORM_NAME, VERSION, BUILD_EDITION, FRONTEND_DIR
)
from backend.app.api.routes import router as api_router

app = FastAPI(
    title=PLATFORM_NAME,
    version=VERSION,
    description=f"{BUILD_EDITION} - Courtroom Admissible Electronic Evidence Platform",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API Routes
app.include_router(api_router)

# Mount Static Frontend Files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serves the primary SOC Forensics Workstation interface."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {
        "platform": PLATFORM_NAME,
        "version": VERSION,
        "status": "OPERATIONAL",
        "message": "Frontend index.html under initialization"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
