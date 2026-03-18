from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import databases
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os

# ─── CONFIG ───────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./gasto.db")
SECRET_KEY   = os.environ.get("SECRET_KEY", "cambia-esta-clave-secreta-en-produccion")
ALGORITHM    = "HS256"
TOKEN_EXPIRE_DAYS = 30

# Railway usa postgres://, SQLAlchemy necesita postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ─── DB SETUP ─────────────────────────────────────────────
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ─── MODELS ───────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id       = Column(Integer, primary_key=True, index=True)
    email    = Column(String, unique=True, index=True, nullable=False)
    name     = Column(String, nullable=False)
    password = Column(String, nullable=False)
    created  = Column(DateTime, default=datetime.utcnow)

class Transaction(Base):
    __tablename__ = "transactions"
    id      = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    desc    = Column(String, nullable=False)
    amount  = Column(Float, nullable=False)
    type    = Column(String, nullable=False)   # gasto | ingreso
    cat     = Column(String, nullable=False)
    date    = Column(String, nullable=False)   # YYYY-MM-DD
    note    = Column(String, default="")
    created = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ─── SCHEMAS ──────────────────────────────────────────────
class RegisterIn(BaseModel):
    email: str
    name: str
    password: str

class LoginIn(BaseModel):
    email: str
    password: str

class TransactionIn(BaseModel):
    desc:   str
    amount: float
    type:   str
    cat:    str
    date:   str
    note:   Optional[str] = ""

class TransactionOut(TransactionIn):
    id: int
    class Config:
        from_attributes = True

# ─── AUTH UTILS ───────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer  = HTTPBearer()

def hash_password(pw: str) -> str:
    return pwd_ctx.hash(pw)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": str(user_id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db)
) -> User:
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user

# ─── APP ──────────────────────────────────────────────────
app = FastAPI(title="GASTO API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # En producción cambia por tu dominio de GitHub Pages
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── ROUTES: AUTH ─────────────────────────────────────────
@app.post("/auth/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    user = User(
        email    = data.email.lower().strip(),
        name     = data.name.strip(),
        password = hash_password(data.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_token(user.id)
    return {"token": token, "name": user.name, "email": user.email}

@app.post("/auth/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower().strip()).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos")
    token = create_token(user.id)
    return {"token": token, "name": user.name, "email": user.email}

@app.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "name": user.name, "email": user.email}

# ─── ROUTES: TRANSACTIONS ─────────────────────────────────
@app.get("/transactions", response_model=List[TransactionOut])
def get_transactions(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Transaction).filter(Transaction.user_id == user.id)\
             .order_by(Transaction.date.desc(), Transaction.created.desc()).all()

@app.post("/transactions", response_model=TransactionOut)
def create_transaction(data: TransactionIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tx = Transaction(user_id=user.id, **data.dict())
    db.add(tx)
    db.commit()
    db.refresh(tx)
    return tx

@app.delete("/transactions/{tx_id}")
def delete_transaction(tx_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tx = db.query(Transaction).filter(Transaction.id == tx_id, Transaction.user_id == user.id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transacción no encontrada")
    db.delete(tx)
    db.commit()
    return {"ok": True}

@app.get("/")
def root():
    return {"status": "GASTO API corriendo"}
