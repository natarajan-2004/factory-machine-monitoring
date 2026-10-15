
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, ConfigDict
from pwdlib import PasswordHash
from sqlalchemy import (
    create_engine, String, Float, Integer, Boolean, DateTime,
    ForeignKey, Text, select, desc
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
log = logging.getLogger("factory-monitor")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./factory_monitor.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

JWT_SECRET = os.getenv("JWT_SECRET", "local-development-secret-change-me")
JWT_ALGORITHM = "HS256"
TOKEN_MINUTES = 8 * 60

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(String(30), default="operator")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class Machine(Base):
    __tablename__ = "machines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    location: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default="running")
    temperature: Mapped[float] = mapped_column(Float, default=42.0)
    vibration: Mapped[float] = mapped_column(Float, default=1.2)
    rpm: Mapped[int] = mapped_column(Integer, default=1450)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class Telemetry(Base):
    __tablename__ = "telemetry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    machine_id: Mapped[int] = mapped_column(ForeignKey("machines.id"), index=True)
    temperature: Mapped[float] = mapped_column(Float)
    vibration: Mapped[float] = mapped_column(Float)
    rpm: Mapped[int] = mapped_column(Integer)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )


class Alarm(Base):
    __tablename__ = "alarms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    machine_id: Mapped[int] = mapped_column(ForeignKey("machines.id"), index=True)
    title: Mapped[str] = mapped_column(String(180))
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="warning")
    state: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_email: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# FIX: Use string email fields so .local demo addresses are accepted.
class LoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=200)


class UserCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=200)
    role: str = "operator"


app = FastAPI(
    title="Factory Machine Monitoring Platform",
    version="1.0.0",
    description="Educational industrial machine monitoring API"
)

origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:8080"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utcnow():
    return datetime.now(timezone.utc)


def to_iso(value):
    return value.isoformat() if value else None


def record_audit(db: Session, actor: str, action: str, detail: str = ""):
    db.add(AuditEvent(actor_email=actor, action=action, detail=detail))
    db.commit()


def create_token(user: User):
    now = utcnow()
    return jwt.encode(
        {
            "sub": user.email,
            "role": user.role,
            "iat": now,
            "exp": now + timedelta(minutes=TOKEN_MINUTES)
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def user_dict(user: User):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "active": user.active
    }


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.scalar(
        select(User).where(User.email == email, User.active == True)
    )
    if not user:
        raise HTTPException(
            status_code=401,
            detail="User is inactive or no longer exists"
        )
    return user


def require_roles(*roles):
    def checker(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail="Your role cannot perform this action"
            )
        return user
    return checker


def machine_dict(m: Machine):
    return {
        "id": m.id,
        "code": m.code,
        "name": m.name,
        "location": m.location,
        "status": m.status,
        "temperature": round(m.temperature, 1),
        "vibration": round(m.vibration, 2),
        "rpm": m.rpm,
        "last_seen": to_iso(m.last_seen)
    }


def alarm_dict(a: Alarm, db: Session):
    m = db.get(Machine, a.machine_id)
    return {
        "id": a.id,
        "machine_id": a.machine_id,
        "machine_code": m.code if m else "Unknown",
        "machine_name": m.name if m else "Unknown",
        "title": a.title,
        "message": a.message,
        "severity": a.severity,
        "state": a.state,
        "created_at": to_iso(a.created_at),
        "acknowledged_by": a.acknowledged_by,
        "acknowledged_at": to_iso(a.acknowledged_at)
    }


def snapshot(db: Session):
    machines = db.scalars(select(Machine).order_by(Machine.id)).all()
    alarms = db.scalars(
        select(Alarm)
        .where(Alarm.state != "cleared")
        .order_by(desc(Alarm.created_at))
        .limit(30)
    ).all()

    return {
        "machines": [machine_dict(m) for m in machines],
        "alarms": [alarm_dict(a, db) for a in alarms],
        "generated_at": to_iso(utcnow())
    }


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        if not db.scalar(select(User.id).limit(1)):
            db.add_all([
                User(
                    name="System Administrator",
                    email="admin@factory.local",
                    password_hash=password_hash.hash("Admin123!"),
                    role="admin"
                ),
                User(
                    name="Line Operator",
                    email="operator@factory.local",
                    password_hash=password_hash.hash("Operator123!"),
                    role="operator"
                ),
                User(
                    name="Maintenance Engineer",
                    email="maintenance@factory.local",
                    password_hash=password_hash.hash("Maint123!"),
                    role="maintenance"
                )
            ])

        if not db.scalar(select(Machine.id).limit(1)):
            db.add_all([
                Machine(
                    code="MCH-001",
                    name="CNC Milling Unit",
                    location="Production · Line A",
                    status="running",
                    temperature=48.2,
                    vibration=1.18,
                    rpm=1480
                ),
                Machine(
                    code="MCH-002",
                    name="Hydraulic Press",
                    location="Production · Line B",
                    status="running",
                    temperature=56.7,
                    vibration=2.35,
                    rpm=920
                ),
                Machine(
                    code="MCH-003",
                    name="Conveyor Motor 03",
                    location="Assembly · Line C",
                    status="stopped",
                    temperature=39.4,
                    vibration=0.42,
                    rpm=0
                )
            ])
            db.commit()

        db.commit()
        machines = db.scalars(select(Machine)).all()

        if not db.scalar(select(Telemetry.id).limit(1)):
            for m in machines:
                for n in range(12):
                    db.add(
                        Telemetry(
                            machine_id=m.id,
                            temperature=m.temperature + random.uniform(-3, 3),
                            vibration=max(
                                0.1, m.vibration + random.uniform(-0.3, 0.3)
                            ),
                            rpm=max(0, m.rpm + random.randint(-35, 35)),
                            recorded_at=utcnow() - timedelta(minutes=(11 - n) * 2)
                        )
                    )

            db.add_all([
                Alarm(
                    machine_id=machines[1].id,
                    title="Vibration above normal",
                    message=(
                        "Hydraulic press vibration is above its typical "
                        "operating range."
                    ),
                    severity="warning",
                    state="active"
                ),
                Alarm(
                    machine_id=machines[2].id,
                    title="Machine stopped",
                    message=(
                        "Conveyor motor is stopped. Verify the production "
                        "schedule and local controls."
                    ),
                    severity="info",
                    state="active"
                )
            ])
            db.commit()

    log.info("Factory monitoring API initialized")


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(select(1))
    redis_status = "not_configured"
    redis_url = os.getenv("REDIS_URL")

    if redis_url:
        try:
            import redis
            redis.Redis.from_url(
                redis_url, socket_connect_timeout=0.3
            ).ping()
            redis_status = "ok"
        except Exception:
            redis_status = "unavailable"

    return {
        "status": "ok",
        "database": "ok",
        "redis": redis_status,
        "timestamp": to_iso(utcnow())
    }


@app.post("/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))

    if (
        not user
        or not user.active
        or not password_hash.verify(body.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=401,
            detail="Email or password is incorrect"
        )

    record_audit(db, user.email, "sign_in", "Successful sign-in")

    return {
        "access_token": create_token(user),
        "token_type": "bearer",
        "user": user_dict(user)
    }


@app.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return user_dict(user)


@app.get("/api/dashboard")
def dashboard(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    machines = db.scalars(select(Machine)).all()
    alarms = db.scalars(
        select(Alarm).where(Alarm.state == "active")
    ).all()

    online_count = 0
    for m in machines:
        last_seen = m.last_seen
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if (utcnow() - last_seen).total_seconds() < 20:
            online_count += 1

    return {
        "total_machines": len(machines),
        "running": sum(m.status == "running" for m in machines),
        "stopped": sum(m.status == "stopped" for m in machines),
        "faulted": sum(m.status == "fault" for m in machines),
        "active_alarms": len(alarms),
        "critical_alarms": sum(a.severity == "critical" for a in alarms),
        "machines_online": online_count
    }


@app.get("/api/machines")
def list_machines(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return [
        machine_dict(m)
        for m in db.scalars(select(Machine).order_by(Machine.id)).all()
    ]


@app.get("/api/machines/{machine_id}")
def machine_detail(
    machine_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    m = db.get(Machine, machine_id)
    if not m:
        raise HTTPException(status_code=404, detail="Machine not found")

    points = db.scalars(
        select(Telemetry)
        .where(Telemetry.machine_id == machine_id)
        .order_by(desc(Telemetry.recorded_at))
        .limit(40)
    ).all()[::-1]

    return {
        "machine": machine_dict(m),
        "telemetry": [
            {
                "temperature": p.temperature,
                "vibration": p.vibration,
                "rpm": p.rpm,
                "recorded_at": to_iso(p.recorded_at)
            }
            for p in points
        ]
    }


@app.get("/api/alarms")
def list_alarms(
    state: str = "all",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    q = select(Alarm).order_by(desc(Alarm.created_at)).limit(100)

    if state in ("active", "acknowledged", "cleared"):
        q = (
            select(Alarm)
            .where(Alarm.state == state)
            .order_by(desc(Alarm.created_at))
            .limit(100)
        )

    return [alarm_dict(a, db) for a in db.scalars(q).all()]


@app.post("/api/alarms/{alarm_id}/acknowledge")
def acknowledge_alarm(
    alarm_id: int,
    user: User = Depends(require_roles("admin", "operator", "maintenance")),
    db: Session = Depends(get_db)
):
    alarm = db.get(Alarm, alarm_id)
    if not alarm:
        raise HTTPException(status_code=404, detail="Alarm not found")

    if alarm.state == "cleared":
        raise HTTPException(
            status_code=409,
            detail="Cleared alarms cannot be acknowledged"
        )

    if alarm.state == "active":
        alarm.state = "acknowledged"
        alarm.acknowledged_by = user.email
        alarm.acknowledged_at = utcnow()
        db.commit()
        record_audit(
            db, user.email, "alarm_acknowledged",
            f"Alarm #{alarm.id}: {alarm.title}"
        )

    return alarm_dict(alarm, db)


@app.get("/api/audit")
def list_audit(
    user: User = Depends(require_roles("admin", "maintenance")),
    db: Session = Depends(get_db)
):
    rows = db.scalars(
        select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(100)
    ).all()

    return [
        {
            "id": x.id,
            "actor_email": x.actor_email,
            "action": x.action,
            "detail": x.detail,
            "created_at": to_iso(x.created_at)
        }
        for x in rows
    ]


@app.get("/api/users")
def list_users(
    user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    return [
        user_dict(x)
        for x in db.scalars(select(User).order_by(User.id)).all()
    ]


@app.post("/api/users", status_code=201)
def create_user(
    body: UserCreate,
    user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    email = body.email.strip().lower()

    if body.role not in ("admin", "operator", "maintenance"):
        raise HTTPException(
            status_code=422,
            detail="Role must be admin, operator, or maintenance"
        )

    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already exists")

    created = User(
        name=body.name,
        email=email,
        password_hash=password_hash.hash(body.password),
        role=body.role
    )

    db.add(created)
    db.commit()
    db.refresh(created)

    record_audit(
        db, user.email, "user_created",
        f"Created {created.email} ({created.role})"
    )

    return user_dict(created)


@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    token = ws.query_params.get("token")

    try:
        payload = jwt.decode(
            token or "", JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )
        email = payload.get("sub")

        with SessionLocal() as db:
            user = db.scalar(
                select(User).where(User.email == email, User.active == True)
            )
            if not user:
                raise ValueError("inactive user")

    except Exception:
        await ws.close(code=1008)
        return

    await ws.accept()

    try:
        while True:
            with SessionLocal() as db:
                data = snapshot(db)

            await ws.send_json(data)
            await asyncio.sleep(3)

    except WebSocketDisconnect:
        log.info("WebSocket disconnected: %s", email)
    except Exception as exc:
        log.warning("WebSocket ended: %s", exc)


async def simulator_loop():
    if os.getenv("SIMULATOR_ENABLED", "true").lower() != "true":
        return

    while True:
        try:
            with SessionLocal() as db:
                machines = db.scalars(select(Machine)).all()

                for m in machines:
                    if m.status == "stopped":
                        m.rpm = 0
                        m.temperature = max(
                            28, m.temperature - random.uniform(0, 0.8)
                        )
                        m.vibration = max(
                            0.1, m.vibration - random.uniform(0, 0.1)
                        )
                    else:
                        m.temperature = max(
                            30, min(88, m.temperature + random.uniform(-1.3, 1.6))
                        )
                        m.vibration = max(
                            0.1, min(5, m.vibration + random.uniform(-0.18, 0.22))
                        )
                        m.rpm = max(
                            0, min(1800, m.rpm + random.randint(-22, 22))
                        )

                        if m.temperature > 76:
                            m.status = "fault"
                        elif m.status == "fault" and m.temperature < 70:
                            m.status = "running"

                    m.last_seen = utcnow()

                    db.add(
                        Telemetry(
                            machine_id=m.id,
                            temperature=m.temperature,
                            vibration=m.vibration,
                            rpm=m.rpm,
                            recorded_at=utcnow()
                        )
                    )

                    old = db.scalars(
                        select(Telemetry.id)
                        .where(Telemetry.machine_id == m.id)
                        .order_by(desc(Telemetry.recorded_at))
                        .offset(500)
                    ).all()

                    if old:
                        db.query(Telemetry).filter(
                            Telemetry.id.in_(old)
                        ).delete(synchronize_session=False)

                db.commit()

                redis_url = os.getenv("REDIS_URL")
                if redis_url:
                    try:
                        import redis
                        redis.Redis.from_url(
                            redis_url, socket_connect_timeout=0.3
                        ).setex(
                            "factory:live_snapshot",
                            10,
                            json.dumps(snapshot(db))
                        )
                    except Exception:
                        pass

        except Exception:
            log.exception("Telemetry simulator iteration failed")

        await asyncio.sleep(3)


@app.on_event("startup")
async def start_simulator():
    asyncio.create_task(simulator_loop())
