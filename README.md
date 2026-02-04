# 🚀 PDFverse - Free PDF Tools

Complete PDF utility platform with Netlify + Render deployment.

## Quick Deploy Guide

### 1️⃣ Deploy Backend to Render (Free)

1. Push `backend/` folder to a GitHub repo
2. Go to [render.com](https://render.com) → New Web Service
3. Connect your repo and configure:
   - **Build**: `chmod +x build.sh && ./build.sh`
   - **Start**: `gunicorn app:app --bind 0.0.0.0:$PORT`
4. Add env var: `SECRET_KEY` (click Generate)
5. Copy your URL: `https://YOUR-APP.onrender.com`

### 2️⃣ Deploy Frontend to Netlify (Free)

1. Edit `frontend/config.js` - update API_URL with your Render URL
2. Push `frontend/` folder to a GitHub repo  
3. Go to [netlify.com](https://netlify.com) → Add new site
4. Connect repo, deploy!

### 3️⃣ Update CORS

Back in Render, add env var:
- `FRONTEND_URL` = `https://YOUR-SITE.netlify.app`

Done! 🎉

## Features
- Images to PDF, Merge, Split, Compress
- Unlock/Protect PDF, Excel to PDF
- Rotate, Watermark, Extract Pages
- JWT Auth, Rate Limiting, Auto-cleanup

## Local Development

```bash
# Backend
cd backend && pip install -r requirements.txt && python app.py

# Frontend  
cd frontend && python -m http.server 3000
```

Files auto-delete after 24 hours. Max 50MB uploads.
