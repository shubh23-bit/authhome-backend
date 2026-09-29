from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware

from app.database.connection import Base, engine, SessionLocal
from app.models.user import User
from app.schemas.user import UserSignup, UserLogin
from app.security.jwt import create_access_token
from app.security.password import hash_password, verify_password
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.security.jwt import create_access_token, verify_access_token

app = FastAPI(title="AuthHome API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer()


# Create database tables
Base.metadata.create_all(bind=engine)


# Database dependency
def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    payload = verify_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    return payload


# Home / health check
@app.get("/")
def home():
    return {
        "message": "AuthHome API is running"
    }


# Database connection test
@app.get("/db-test")
def db_test():
    with engine.connect() as connection:
        result = connection.execute(text("SELECT 1"))

        return {
            "database": "connected",
            "result": result.scalar()
        }


# Signup
@app.post("/signup")
def signup(
    user: UserSignup,
    db: Session = Depends(get_db)
):
    # Check whether email already exists
    existing_user = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # Hash password before storing it
    hashed_password = hash_password(user.password)

    # Create new user
    new_user = User(
        name=user.name,
        email=user.email,
        password=hashed_password
    )

    # Save user to database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email
        }
    }
@app.post("/login")
def login(
    user: UserLogin,
    db: Session = Depends(get_db)
):
    # Find user by email
    existing_user = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if not existing_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    # Verify password
    password_valid = verify_password(
        user.password,
        existing_user.password
    )

    if not password_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    # Create JWT
    access_token = create_access_token(
        data={
            "sub": existing_user.email,
            "user_id": existing_user.id
        }
    )

    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer"
    }
@app.get("/home")
def protected_home(
    current_user: dict = Depends(get_current_user)
):
    return {
        "message": "Welcome to the protected home page",
        "user_id": current_user["user_id"],
        "email": current_user["sub"]
    }