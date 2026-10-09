"""Authenticated API for receiving local endpoint-sensor metadata."""

from datetime import datetime, timezone
import hmac
import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./cti_backend.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
security = HTTPBearer(auto_error=False)
app = FastAPI(title="AI Cyber Threat Intelligence API", version="1.0.0")


class Base(DeclarativeBase):
    pass


class EndpointEvent(Base):
    __tablename__ = "endpoint_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    sensor_id: Mapped[str] = mapped_column(String(80), index=True)
    occurred_at: Mapped[str] = mapped_column(String(40), index=True)
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    summary: Mapped[str] = mapped_column(String(500))
    folder: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    file_name: Mapped[Optional[str]] = mapped_column(String(260), nullable=True)
    file_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(260), nullable=True)
    remote_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    remote_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)


class EventIn(BaseModel):
    event_id: str = Field(min_length=1, max_length=120)
    sensor_id: str = Field(min_length=1, max_length=80)
    occurred_at: str = Field(min_length=1, max_length=40)
    event_type: str = Field(min_length=1, max_length=50)
    severity: str = Field(min_length=1, max_length=20)
    summary: str = Field(min_length=1, max_length=500)
    folder: Optional[str] = Field(default=None, max_length=80)
    file_name: Optional[str] = Field(default=None, max_length=260)
    file_sha256: Optional[str] = Field(default=None, min_length=64, max_length=64)
    process_name: Optional[str] = Field(default=None, max_length=260)
    remote_ip: Optional[str] = Field(default=None, max_length=64)
    remote_port: Optional[int] = Field(default=None, ge=1, le=65535)
    risk_score: int = Field(default=0, ge=0, le=100)
    details: Optional[str] = Field(default=None, max_length=2000)


class EventBatch(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=200)


def require_api_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    expected = os.environ.get("API_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API_TOKEN is not configured with a strong value.",
        )
    supplied = credentials.credentials if credentials else ""
    if credentials is None or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/health")
def health():
    return {"status": "ok", "service": "cti-api"}


@app.post("/v1/events")
def ingest_events(batch: EventBatch, _token: None = Depends(require_api_token)):
    inserted = 0
    with SessionLocal() as session:
        for item in batch.events:
            if session.scalar(select(EndpointEvent.id).where(EndpointEvent.event_id == item.event_id)):
                continue
            session.add(EndpointEvent(**item.model_dump()))
            inserted += 1
        session.commit()
    return {"accepted": inserted, "received": len(batch.events)}


@app.get("/v1/events")
def list_events(
    limit: int = 200,
    _token: None = Depends(require_api_token),
):
    limit = max(1, min(int(limit), 1000))
    with SessionLocal() as session:
        rows = session.scalars(
            select(EndpointEvent).order_by(EndpointEvent.id.desc()).limit(limit)
        ).all()
        return {
            "events": [
                {
                    "id": row.id,
                    "event_id": row.event_id,
                    "sensor_id": row.sensor_id,
                    "occurred_at": row.occurred_at,
                    "event_type": row.event_type,
                    "severity": row.severity,
                    "summary": row.summary,
                    "folder": row.folder,
                    "file_name": row.file_name,
                    "file_sha256": row.file_sha256,
                    "process_name": row.process_name,
                    "remote_ip": row.remote_ip,
                    "remote_port": row.remote_port,
                    "risk_score": row.risk_score,
                    "details": row.details,
                }
                for row in rows
            ]
        }
