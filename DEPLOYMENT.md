# 🚀 Free Deployment Guide for PDFverse

This guide covers deploying PDFverse on **100% FREE** hosting platforms.

---

## Option 1: Railway (Recommended) 🚂

Railway offers a free tier with $5 monthly credit - enough for a small PDF tool.

### Steps:
1. Create account at [railway.app](https://railway.app)
2. Click "New Project" → "Deploy from GitHub repo"
3. Connect your GitHub and select the PDFverse repository
4. Railway auto-detects Python and deploys
5. Add environment variables in Settings:
   - `SECRET_KEY`: Generate with `python -c "import secrets; print(secrets.token_hex(32))"`
6. Your app will be live at `your-app.railway.app`

---

## Option 2: Render 🎨

Render offers a generous free tier.

### Steps:
1. Create account at [render.com](https://render.com)
2. New → Web Service → Connect GitHub repo
3. Configure:
   - **Build Command**: `pip install -r backend/requirements.txt`
   - **Start Command**: `cd backend && gunicorn app:app`
4. Add environment variable `SECRET_KEY`
5. Deploy!

### For Frontend:
1. New → Static Site
2. Connect to same repo
3. **Publish directory**: `frontend`

---

## Option 3: Fly.io 🪰

Fly.io offers free allowances.

### Steps:
1. Install flyctl: `curl -L https://fly.io/install.sh | sh`
2. Login: `fly auth login`
3. Create `fly.toml`:
```toml
app = "pdfverse"
primary_region = "ord"

[build]
  dockerfile = "Dockerfile"

[env]
  PORT = "5000"

[http_service]
  internal_port = 5000
  force_https = true

[[services]]
  internal_port = 5000
  protocol = "tcp"

  [[services.ports]]
    port = 80
    handlers = ["http"]

  [[services.ports]]
    port = 443
    handlers = ["tls", "http"]
```
4. Deploy: `fly launch`
5. Set secrets: `fly secrets set SECRET_KEY=your-secret-key`

---

## Option 4: PythonAnywhere 🐍

Great for Python apps, has a free tier.

### Steps:
1. Create account at [pythonanywhere.com](https://www.pythonanywhere.com)
2. Go to "Web" tab → "Add a new web app"
3. Choose "Flask" and Python 3.10
4. Upload your backend files
5. Configure WSGI:
```python
import sys
path = '/home/yourusername/pdfverse/backend'
if path not in sys.path:
    sys.path.append(path)

from app import app as application
```
6. Set up virtual environment and install requirements
7. Reload the web app

**Note**: Free tier has limited CPU and storage.

---

## Option 5: Vercel + PythonAnywhere Split 🔀

Best performance: Vercel for frontend, PythonAnywhere for backend.

### Frontend on Vercel:
1. Create account at [vercel.com](https://vercel.com)
2. Import GitHub repo
3. Set root directory to `frontend`
4. Deploy (instant!)

### Backend on PythonAnywhere:
Follow Option 4 above.

### Update Frontend API URL:
In `frontend/index.html`, change:
```javascript
const API_BASE_URL = 'https://yourusername.pythonanywhere.com/api';
```

---

## Option 6: GitHub Pages + Glitch 🎲

### Frontend on GitHub Pages:
1. Enable GitHub Pages in repo settings
2. Set source to main branch, `/frontend` folder
3. Access at `yourusername.github.io/pdfverse`

### Backend on Glitch:
1. Create account at [glitch.com](https://glitch.com)
2. New Project → Import from GitHub
3. Glitch auto-runs Python apps

---

## 🔧 Post-Deployment Checklist

- [ ] Set strong `SECRET_KEY` in environment
- [ ] Update CORS origins to your domain
- [ ] Test all PDF tools
- [ ] Verify file cleanup is working
- [ ] Set up monitoring (free options: UptimeRobot, Freshping)
- [ ] Enable HTTPS (most platforms do this automatically)

---

## 💡 Cost Comparison

| Platform | Free Tier | Best For |
|----------|-----------|----------|
| Railway | $5/month credit | All-in-one |
| Render | 750 hours/month | Backend |
| Fly.io | 3 VMs free | Docker apps |
| PythonAnywhere | Limited CPU | Python apps |
| Vercel | Unlimited static | Frontend |
| GitHub Pages | Unlimited | Static files |
| Glitch | Always-on free | Small apps |

---

## 🔐 Security Reminders

1. **Never commit `.env` files** to GitHub
2. **Always use HTTPS** in production
3. **Rotate SECRET_KEY** periodically
4. **Monitor for abuse** (rate limiting is built-in)
5. **Keep dependencies updated**

---

## 📞 Need Help?

- Check platform-specific documentation
- Join Discord communities for each platform
- Stack Overflow for common issues

---

Happy deploying! 🎉
