# 🧠 Empathetic AI Chatbot

An AI-powered chatbot that detects emotions and responds with empathy using Google's Gemini AI. Built with FastAPI backend and Next.js frontend.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![Next.js](https://img.shields.io/badge/Next.js-16-black.svg)

## ✨ Features

- 🎭 **Emotion Detection** - Automatically detects user emotions (joy, sadness, anger, fear, neutral)
- 💬 **Empathetic Responses** - AI responds with appropriate empathy strategies
- 🔐 **Secure Authentication** - JWT-based auth with bcrypt password hashing
- 🔑 **Google OAuth** - Sign in with Google support
- 📊 **Emotion Analytics** - Track emotional patterns over time
- ⚡ **Real-time Chat** - WebSocket support for instant messaging
- 🛡️ **Rate Limiting** - Protection against abuse

## 🛠️ Tech Stack

### Backend
- **FastAPI** - Modern Python web framework
- **SQLAlchemy** - Database ORM
- **Redis** - Caching and rate limiting
- **Google Gemini AI** - AI responses
- **bcrypt** - Secure password hashing

### Frontend
- **Next.js 16** - React framework
- **React 19** - UI library
- **TailwindCSS** - Styling
- **Lucide React** - Icons

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Node.js 18+
- Redis server
- Google Gemini API key
- Google OAuth credentials (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/emotion-ai.git
   cd emotion-ai
   ```

2. **Backend Setup**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Frontend Setup**
   ```bash
   cd frontend
   npm install
   ```

5. **Start Redis**
   ```bash
   redis-server
   ```

6. **Run the Application**
   
   Backend:
   ```bash
   cd backend
   uvicorn empathetic_ai:app --reload
   ```
   
   Frontend:
   ```bash
   cd frontend
   npm run dev
   ```

7. **Open** http://localhost:3000

## 📝 Environment Variables

### Backend (.env)

| Variable | Description |
|----------|-------------|
| `GEMINI_API_KEY` | Google Gemini API key |
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth Client Secret |
| `SECRET_KEY` | JWT signing key (use `secrets.token_hex(32)`) |
| `SESSION_SECRET` | Session signing key |
| `DATABASE_URL` | Database connection string |
| `REDIS_URL` | Redis connection string |
| `FRONTEND_URL` | Frontend URL for CORS |
| `BACKEND_URL` | Backend URL |
| `GOOGLE_REDIRECT_URI` | OAuth callback URL |

### Frontend (.env.local)

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_API_URL` | Backend API URL |
| `NEXT_PUBLIC_WS_URL` | WebSocket URL |

## 🔒 Security Features

- ✅ bcrypt password hashing
- ✅ JWT access & refresh tokens
- ✅ Rate limiting (5 auth attempts/15 min, 30 messages/min)
- ✅ Input validation
- ✅ Security headers (X-Frame-Options, X-XSS-Protection)
- ✅ CORS protection
- ✅ Secure OAuth code exchange

## 📁 Project Structure

```
emotion-ai/
├── backend/
│   ├── empathetic_ai.py    # Main FastAPI application
│   ├── requirements.txt    # Python dependencies
│   ├── .env.example        # Environment template
│   └── .gitignore
├── frontend/
│   ├── app/
│   │   ├── page.jsx        # Main chat page
│   │   ├── signup/         # Signup page
│   │   └── auth/callback/  # OAuth callback
│   ├── package.json
│   └── .env.example
├── LICENSE
└── README.md
```

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/signup` | Create new user |
| POST | `/login` | User login |
| POST | `/chat` | Send message |
| POST | `/refresh` | Refresh access token |
| GET | `/analytics` | Get emotion analytics |
| GET | `/auth/google` | Google OAuth login |
| GET | `/health` | Health check |
| WS | `/ws/chat` | WebSocket chat |

## 📊 Emotion Detection

The chatbot detects the following emotions:

| Emotion | Trigger Words | Strategy |
|---------|--------------|----------|
| 😢 Sadness | sad, empty, lost | Comfort |
| 😠 Anger | angry, mad | Validation |
| 😨 Fear | fear, anxious | Reassurance |
| 😊 Joy | happy, good | Celebration |
| 😐 Neutral | (default) | Listening |

## 🚀 Deployment

### Recommended Stack

- **Frontend**: [Vercel](https://vercel.com)
- **Backend**: [Railway](https://railway.app)
- **Database**: [Supabase](https://supabase.com) (PostgreSQL)
- **Redis**: [Upstash](https://upstash.com)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Sayon Manna**

---

⭐ Star this repo if you found it helpful!
