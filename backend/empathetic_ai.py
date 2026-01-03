from fastapi import FastAPI, WebSocket, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from jose import jwt, JWTError
from datetime import datetime, timedelta
from authlib.integrations.starlette_client import OAuth
import google.generativeai as genai
import redis
import subprocess
import os
import json
import uuid
import re
import bcrypt
from dotenv import load_dotenv
load_dotenv()

# DATABASE
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# ==================== SECURITY: Environment Variables ====================
# Validate required environment variables
def get_required_env(key: str) -> str:
    value = os.getenv(key)
    if not value:
        raise ValueError(f"Required environment variable {key} is not set")
    return value

# Security keys from environment (NEVER hardcode!)
SECRET_KEY = get_required_env("SECRET_KEY")
SESSION_SECRET = get_required_env("SESSION_SECRET")

# Optional with defaults for development
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///empathetic_ai.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# ==================== APP + CORS ====================
app = FastAPI()
from starlette.middleware.sessions import SessionMiddleware
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# Security: Restrict CORS to known origins
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001", 
    "http://127.0.0.1:3000",
    FRONTEND_URL,
]
# Remove duplicates and empty strings
ALLOWED_ORIGINS = list(set(filter(None, ALLOWED_ORIGINS)))

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# ==================== Security Headers Middleware ====================
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# ==================== REDIS ====================
redis_db = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# ==================== DATABASE (SQLite/PostgreSQL) ====================
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class ConversationLog(Base):
    __tablename__ = "conversation_logs"
    id = Column(Integer, primary_key=True)
    user = Column(String)
    agent = Column(String)
    message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class MemorySummary(Base):
    __tablename__ = "memory_summaries"
    id = Column(Integer, primary_key=True)
    user = Column(String)
    summary = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)

# ==================== SECURITY: Input Validation ====================
def validate_username(username: str) -> tuple[bool, str]:
    """Validate username format."""
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 30:
        return False, "Username must be less than 30 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, ""

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength."""
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    return True, ""

def validate_message(message: str) -> tuple[bool, str]:
    """Validate chat message."""
    if not message or not message.strip():
        return False, "Message cannot be empty"
    if len(message) > 5000:
        return False, "Message must be less than 5000 characters"
    return True, ""

# ==================== SECURITY: Password Hashing (bcrypt) ====================
def hash_password(password: str) -> str:
    """Hash password using bcrypt (secure, with salt)."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

# ==================== SECURITY: Rate Limiting ====================
def rate_limit_auth(identifier: str) -> bool:
    """Rate limit authentication attempts (5 per 15 minutes)."""
    key = f"auth_rate:{identifier}"
    count = redis_db.incr(key)
    if count == 1:
        redis_db.expire(key, 900)  # 15 minutes
    return count <= 5

def rate_limit_chat(user: str) -> bool:
    """Rate limit chat messages (30 per minute)."""
    key = f"rate:{user}"
    count = redis_db.incr(key)
    if count == 1:
        redis_db.expire(key, 60)
    return count <= 30

# ==================== AUTH CONFIG ====================
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

def create_access_token(user: str):
    payload = {
        "sub": user,
        "type": "access",
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user: str):
    jti = str(uuid.uuid4())
    payload = {
        "sub": user,
        "jti": jti,
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    redis_db.setex(f"refresh:{jti}", REFRESH_TOKEN_EXPIRE_DAYS * 86400, user)
    return token

def get_user_from_token(token: str, expected="access"):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != expected:
            return None
        return payload.get("sub")
    except JWTError:
        return None

# ==================== SIGNUP + LOGIN ENDPOINTS ====================
@app.post("/signup")
def signup(data: dict):
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    # Validate inputs
    valid, error = validate_username(username)
    if not valid:
        return {"error": error}
    
    valid, error = validate_password(password)
    if not valid:
        return {"error": error}
    
    # Rate limit by IP (if available) or username
    if not rate_limit_auth(username):
        return {"error": "Too many attempts. Please try again in 15 minutes."}
    
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            return {"error": "Username already exists"}
        
        user = User(username=username, password_hash=hash_password(password))
        db.add(user)
        db.commit()
        
        return {
            "message": "User created successfully",
            "access_token": create_access_token(username),
            "refresh_token": create_refresh_token(username),
        }
    finally:
        db.close()

@app.post("/login")
def login(data: dict):
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        return {"error": "Username and password required"}
    
    # Rate limit authentication attempts
    if not rate_limit_auth(username):
        return {"error": "Too many login attempts. Please try again in 15 minutes."}
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        
        if not user or not verify_password(password, user.password_hash):
            return {"error": "Invalid credentials"}
        
        return {
            "access_token": create_access_token(username),
            "refresh_token": create_refresh_token(username),
        }
    finally:
        db.close()

# ==================== GOOGLE OAUTH ====================
from starlette.config import Config

# Use environ for production (no .env file needed)
config = Config(environ=os.environ)
oauth = OAuth(config)
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

@app.get("/auth/google")
async def google_login(request: Request):
    try:
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", f"{BACKEND_URL}/auth/google/callback")
        return await oauth.google.authorize_redirect(request, redirect_uri)
    except Exception as e:
        print(f"Google OAuth error: {e}")
        return {"error": str(e)}

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")
        if not user_info:
            return {"error": "Failed to get user info"}
        
        email = user_info.get("email")
        if not email:
            return {"error": "No email in user info"}
        
        # Generate tokens
        access_token = create_access_token(email)
        refresh_token = create_refresh_token(email)
        
        # SECURITY: Use temporary code instead of exposing tokens in URL
        temp_code = str(uuid.uuid4())
        redis_db.setex(
            f"oauth_code:{temp_code}",
            300,  # 5 minutes expiry
            json.dumps({"access": access_token, "refresh": refresh_token})
        )
        
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"{FRONTEND_URL}/auth/callback?code={temp_code}")
    except Exception as e:
        print(f"Google callback error: {e}")
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"{FRONTEND_URL}?error=oauth_failed")

# ==================== OAUTH CODE EXCHANGE ====================
@app.post("/auth/exchange")
def exchange_oauth_code(data: dict):
    """Exchange temporary OAuth code for tokens (more secure than URL params)."""
    code = data.get("code", "")
    if not code:
        return {"error": "Code is required"}
    
    # Get and delete the code (one-time use)
    token_data = redis_db.get(f"oauth_code:{code}")
    if not token_data:
        return {"error": "Invalid or expired code"}
    
    redis_db.delete(f"oauth_code:{code}")
    
    try:
        tokens = json.loads(token_data)
        return {
            "access_token": tokens.get("access"),
            "refresh_token": tokens.get("refresh"),
        }
    except json.JSONDecodeError:
        return {"error": "Invalid token data"}

# ==================== REFRESH TOKEN ====================
@app.post("/refresh")
def refresh(data: dict):
    refresh_token = data.get("refresh_token")
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        user = redis_db.get(f"refresh:{jti}")
        if not user:
            return {"error": "Invalid refresh token"}
        return {"access_token": create_access_token(user)}
    except JWTError:
        return {"error": "Invalid refresh token"}

# ==================== AI SERVICES: GEMINI + OPENROUTER + HUGGINGFACE ====================
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

def gemini(prompt: str):
    """Call Gemini API - try multiple models."""
    models_to_try = [
        "gemini-1.5-pro",
        "gemini-1.5-flash", 
        "gemini-pro",
        "models/gemini-pro",
    ]
    
    last_error = None
    for model_name in models_to_try:
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(prompt)
            if response and response.text:
                return response.text
        except Exception as e:
            last_error = e
            print(f"Gemini model {model_name} failed: {e}")
            continue
    
    raise Exception(f"All Gemini models failed. Last error: {last_error}")

def openrouter(prompt: str):
    """Call OpenRouter API - unified access to multiple AI models."""
    import requests
    
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY not set")
    
    # OpenRouter provides access to many models - try free/cheap ones
    models_to_try = [
        "mistralai/mistral-7b-instruct:free",
        "google/gemma-7b-it:free",
        "huggingfaceh4/zephyr-7b-beta:free",
        "openchat/openchat-7b:free",
    ]
    
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": os.getenv("FRONTEND_URL", "http://localhost:3000"),
        "X-Title": "Empathetic AI Chatbot"
    }
    
    last_error = None
    for model in models_to_try:
        try:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are an empathetic AI assistant that provides emotional support."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 200,
                "temperature": 0.7
            }
            
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("choices") and len(result["choices"]) > 0:
                    return result["choices"][0]["message"]["content"].strip()
        except Exception as e:
            last_error = e
            print(f"OpenRouter model {model} failed: {e}")
            continue
    
    raise Exception(f"All OpenRouter models failed. Last error: {last_error}")

def huggingface(prompt: str):
    """Call Hugging Face Inference API as cloud fallback."""
    import requests
    
    HF_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
    if not HF_API_KEY:
        raise ValueError("HUGGINGFACE_API_KEY not set")
    
    # Use Hugging Face's free inference models
    models = [
        "HuggingFaceH4/zephyr-7b-beta",
        "microsoft/DialoGPT-large",
        "facebook/blenderbot-400M-distill",
    ]
    
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    
    for model_name in models:
        try:
            API_URL = f"https://api-inference.huggingface.co/models/{model_name}"
            
            payload = {
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": 150,
                    "temperature": 0.7,
                    "return_full_text": False
                }
            }
            
            response = requests.post(API_URL, headers=headers, json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    return result[0].get("generated_text", "").strip()
                return str(result)
        except Exception as e:
            print(f"HuggingFace model {model_name} failed: {e}")
            continue
    
    raise Exception("All HuggingFace models failed")

def emotion_agent(text: str):
    """Detect emotion from text using keyword matching."""
    t = text.lower()
    
    # Sadness keywords
    if any(w in t for w in ["sad", "empty", "lost", "depressed", "lonely", "crying", "tears", "hopeless", "hurt", "broken", "miss", "grief"]):
        return "sadness"
    
    # Anger keywords  
    if any(w in t for w in ["angry", "mad", "furious", "annoyed", "frustrated", "hate", "pissed", "irritated", "rage"]):
        return "anger"
    
    # Fear/anxiety keywords
    if any(w in t for w in ["fear", "anxious", "scared", "worried", "nervous", "panic", "stress", "overwhelmed", "terrified", "afraid"]):
        return "fear"
    
    # Joy keywords
    if any(w in t for w in ["happy", "good", "great", "excited", "wonderful", "amazing", "love", "joy", "blessed", "grateful", "awesome"]):
        return "joy"
    
    # Check for question patterns (follow-up questions)
    if any(w in t for w in ["what should", "how do", "how can", "what can", "any advice", "help me", "suggest"]):
        return "seeking_advice"
    
    return "neutral"

def empathy_agent(emotion: str):
    return {
        "sadness": "comfort",
        "anger": "validation",
        "fear": "reassurance",
        "joy": "celebration",
        "neutral": "listening",
        "seeking_advice": "guidance",
    }.get(emotion, "listening")

def response_agent(message, emotion, strategy):
    """Generate empathetic response using AI with better prompting."""
    
    # Better prompt with more context
    prompt = f"""You are an empathetic AI assistant. Your role is to provide emotional support and helpful advice.

Current situation:
- User's message: "{message}"
- Detected emotion: {emotion}
- Empathy strategy to use: {strategy}

Guidelines:
- Be warm, caring, and understanding
- If the user is asking for advice, provide practical suggestions
- Keep your response conversational and natural (2-4 sentences)
- Don't just acknowledge feelings, also offer helpful perspectives or advice when appropriate

Respond now:"""
    # Try Gemini first (primary)
    try:
        return gemini(prompt)
    except Exception as e:
        print(f"Gemini error: {e}")
    
    # Try Hugging Face (cloud fallback)
    try:
        return huggingface(prompt)
    except Exception as e:
        print(f"Hugging Face error: {e}")
    
    # Try OpenRouter (unified API fallback)
    try:
        return openrouter(prompt)
    except Exception as e:
        print(f"OpenRouter error: {e}")
    
    # Final fallback - improved responses with advice
    fallbacks = {
        "sadness": "I hear you, and I want you to know that your feelings are completely valid. When we're feeling down, it can help to talk to someone we trust, take a gentle walk, or simply allow ourselves to feel without judgment. What do you think might help you feel a bit better right now?",
        "anger": "I understand you're feeling frustrated, and that makes total sense. When we're angry, it sometimes helps to take a few deep breaths, step away from the situation for a moment, or express those feelings in a healthy way like talking it out. What happened that made you feel this way?",
        "fear": "It's completely natural to feel anxious sometimes. Remember that you've gotten through difficult times before, and you have the strength to handle this too. Would it help to break down what's worrying you into smaller, more manageable pieces?",
        "joy": "That's wonderful to hear! I'm genuinely happy that you're feeling good! Savoring these positive moments is so important. What's contributing to your happiness today?",
        "neutral": "I'm here and ready to listen. Sometimes just talking things through can help bring clarity. What's on your mind?",
        "seeking_advice": "I'd love to help you think through this. Could you share a bit more about the situation? The more context you give me, the better I can offer suggestions that might actually be useful for you.",
    }
    return fallbacks.get(emotion, "I'm here to listen and help however I can. Please tell me more about what's going on.")

def log_agent(user, agent, message):
    db = SessionLocal()
    try:
        db.add(ConversationLog(user=user, agent=agent, message=message))
        db.commit()
    finally:
        db.close()

def summarize_long_term(user):
    logs = redis_db.lrange(f"timeline:{user}", -20, -1)
    emotions = ", ".join(json.loads(x)["emotion"] for x in logs)

    prompt = f"Summarize emotional pattern briefly: {emotions}"
    try:
        summary = gemini(prompt)
    except:
        try:
            summary = openrouter(prompt)
        except:
            summary = "Unable to generate summary at this time."

    db = SessionLocal()
    try:
        db.add(MemorySummary(user=user, summary=summary))
        db.commit()
    finally:
        db.close()

# ==================== CHAT ENDPOINT ====================
@app.post("/chat")
def chat(data: dict):
    user = get_user_from_token(data.get("token"))
    if not user:
        return {"error": "Unauthorized"}

    if not rate_limit_chat(user):
        return {"error": "Rate limit exceeded. Please wait a moment."}

    message = data.get("message", "").strip()
    
    # Validate message
    valid, error = validate_message(message)
    if not valid:
        return {"error": error}

    emotion = emotion_agent(message)
    log_agent(user, "emotion_agent", emotion)

    strategy = empathy_agent(emotion)
    log_agent(user, "empathy_agent", strategy)

    redis_db.rpush(
        f"timeline:{user}",
        json.dumps({"emotion": emotion, "time": datetime.utcnow().isoformat()}),
    )
    redis_db.hincrby(f"heatmap:{user}", emotion, 1)

    if redis_db.llen(f"timeline:{user}") % 20 == 0:
        summarize_long_term(user)

    response = response_agent(message, emotion, strategy)
    log_agent(user, "response_agent", response)

    return {
        "emotion": emotion,
        "strategy": strategy,
        "response": response,
    }

# ==================== ANALYTICS ENDPOINT ====================
@app.get("/analytics")
def analytics(token: str):
    user = get_user_from_token(token)
    if not user:
        return {"error": "Unauthorized"}

    timeline = [
        json.loads(x)
        for x in redis_db.lrange(f"timeline:{user}", 0, -1)
    ]
    heatmap = redis_db.hgetall(f"heatmap:{user}")

    return {"timeline": timeline, "heatmap": heatmap}

# ==================== WEBSOCKET CHAT ====================
@app.websocket("/ws/chat")
async def ws_chat(ws: WebSocket):
    await ws.accept()
    while True:
        try:
            data = await ws.receive_json()
            user = get_user_from_token(data.get("token"))
            if not user:
                await ws.send_json({"error": "Unauthorized"})
                continue

            await ws.send_json({"type": "typing"})

            message = data.get("message", "").strip()
            
            # Validate message
            valid, error = validate_message(message)
            if not valid:
                await ws.send_json({"error": error})
                continue

            emotion = emotion_agent(message)
            strategy = empathy_agent(emotion)
            response = response_agent(message, emotion, strategy)

            await ws.send_json({
                "type": "response",
                "data": {
                    "emotion": emotion,
                    "strategy": strategy,
                    "response": response,
                },
            })
        except Exception as e:
            print(f"WebSocket error: {e}")
            await ws.send_json({
                "type": "response",
                "data": {
                    "emotion": "neutral",
                    "strategy": "listening",
                    "response": "I'm having a moment. Could you please try again?",
                },
            })

# ==================== HEALTH CHECK ====================
@app.get("/")
def root():
    return {"status": "Backend running", "docs": "/docs"}

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)

@app.get("/health")
def health():
    """Health check endpoint for deployment platforms."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}