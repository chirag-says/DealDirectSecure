# 🚀 DealDirect - Hostinger Deployment Guide

This guide covers deploying all three parts of the DealDirect application to Hostinger:
- **Backend** (Express.js API Server)
- **Client** (React/Vite Frontend)
- **Admin** (React/Vite Admin Panel)

---

## 📋 Prerequisites

1. **Hostinger Account** with Business Web Hosting or Cloud Hosting plan
2. **GitHub Account** with repositories for each project
3. **MongoDB Atlas** database (already set up)
4. **Cloudinary** account for image uploads (already set up)

---

## 🏗️ Project Structure

You will deploy **3 separate websites** on Hostinger:

| Project | Type | Domain |
|---------|------|--------|
| Backend | Express.js | `backend.dealdirect.in` |
| Client | Vite/React | `dealdirect.in` |
| Admin | Vite/React | `admin.dealdirect.in` |

---

## 📁 Step 1: Prepare GitHub Repositories

Create **3 separate GitHub repositories**:

### 1.1 Backend Repository
```bash
cd backend
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/dealdirect-backend.git
git push -u origin main
```

### 1.2 Client Repository
```bash
cd client
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/dealdirect-client.git
git push -u origin main
```

### 1.3 Admin Repository
```bash
cd Admin
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/dealdirect-admin.git
git push -u origin main
```

---

## 🔧 Step 2: Deploy Backend API (Express.js)

### 2.1 Deploy on Hostinger

1. Log in to **hPanel**
2. Go to **Websites** → **Add Website**
3. Select **Node.js Apps**
4. Choose **Import Git Repository**
5. Authorize GitHub and select your `dealdirect-backend` repository

### 2.2 Configure Build Settings

| Setting | Value |
|---------|-------|
| Framework | Express.js |
| Node Version | 20.x (recommended) |
| Build Command | `npm install` |
| Start Command | `npm start` |
| Root Directory | `/` |

### 2.3 Set Environment Variables

In Hostinger hPanel → **Environment Variables**, add:

```
PORT=9000
NODE_ENV=production
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/database
JWT_SECRET=your-64-character-secret-key
CLOUDINARY_URL=cloudinary://api_key:api_secret@cloud_name
SMTP_USER=your-email@gmail.com
SMTP_EMAIL=your-email@gmail.com
SMTP_PASS=your-app-password
SENDER_EMAIL=your-email@gmail.com
GEMINI_API_KEY=your-gemini-key
MAPPLES_API_KEY=your-mapples-key
AGREEMENT_SECRET_KEY=your-agreement-key
CLIENT_URL=https://dealdirect.in
ADMIN_URL=https://admin.dealdirect.in
```

### 2.4 Deploy

Click **Deploy** and wait for the build to complete.

**Your backend will be available at:** `https://backend.dealdirect.in`

### 2.5 Connect Custom Domain

Your custom domain `backend.dealdirect.in` is already configured in Hostinger.

---

## 🌐 Step 3: Deploy Client (React/Vite)

### 3.1 Update Environment Variables

Before pushing to GitHub, update `.env.production`:

```env
VITE_API_BASE=https://backend.dealdirect.in
VITE_API_URL=https://backend.dealdirect.in/api
VITE_MAPPLES_API_KEY=your-mapples-api-key
```

### 3.2 Deploy on Hostinger

1. Go to **Websites** → **Add Website**
2. Select **Node.js Apps**
3. Choose **Import Git Repository**
4. Select your `dealdirect-client` repository

### 3.3 Configure Build Settings

| Setting | Value |
|---------|-------|
| Framework | Vite |
| Node Version | 20.x |
| Build Command | `npm install && npm run build` |
| Output Directory | `dist` |
| Root Directory | `/` |

### 3.4 Set Environment Variables

In hPanel → **Environment Variables**:

```
VITE_API_BASE=https://backend.dealdirect.in
VITE_API_URL=https://backend.dealdirect.in/api
VITE_MAPPLES_API_KEY=your-mapples-api-key
```

### 3.5 Deploy

Click **Deploy** and wait for the build.

**Your client will be available at:** `https://dealdirect.in`

---

## 👨‍💼 Step 4: Deploy Admin Panel (React/Vite)

### 4.1 Update Environment Variables

Before pushing to GitHub, update `.env.production`:

```env
VITE_API_BASE_URL=https://backend.dealdirect.in
```

### 4.2 Deploy on Hostinger

1. Go to **Websites** → **Add Website**
2. Select **Node.js Apps**
3. Choose **Import Git Repository**
4. Select your `dealdirect-admin` repository

### 4.3 Configure Build Settings

| Setting | Value |
|---------|-------|
| Framework | Vite |
| Node Version | 20.x |
| Build Command | `npm install && npm run build` |
| Output Directory | `dist` |
| Root Directory | `/` |

### 4.4 Set Environment Variables

```
VITE_API_BASE_URL=https://backend.dealdirect.in
```

### 4.5 Deploy

Click **Deploy** and wait for the build.

**Your admin panel will be available at:** `https://admin.dealdirect.in`

---

## 🔗 Step 5: Update Backend CORS Settings

After deploying all three, update your backend environment variables:

```
CLIENT_URL=https://dealdirect.in
ADMIN_URL=https://admin.dealdirect.in
```

Redeploy the backend to apply the CORS changes.

---

## ✅ Verification Checklist

After deployment, verify each component:

### Backend (`backend.dealdirect.in`)
- [ ] Health check: `https://backend.dealdirect.in/health`
- [ ] Debug endpoint: `https://backend.dealdirect.in/debug-startup`
- [ ] API responds to requests
- [ ] Database connection working

### Client (`dealdirect.in`)
- [ ] Homepage loads
- [ ] Can login/register
- [ ] Can view properties
- [ ] Images load from Cloudinary

### Admin (`admin.dealdirect.in`)
- [ ] Login page loads
- [ ] Can login as admin
- [ ] Dashboard displays data

---

## 🔧 Troubleshooting

### Build Fails on Hostinger

1. **Check Node Version**: Ensure you're using Node 18.x or 20.x
2. **Check Build Logs**: Click "See Details" on deployment
3. **Memory Issues**: Large projects may need Cloud hosting

### CORS Errors

1. Verify `CLIENT_URL` and `ADMIN_URL` match your deployed domains
2. Include `https://` prefix
3. No trailing slash

### API Connection Issues

1. Verify `VITE_API_BASE` and `VITE_API_URL` are correct
2. Check if backend is running
3. Check browser console for errors

### 404 Errors on Page Refresh

The `_redirects` file in `/public` folder handles SPA routing.
If issues persist, configure rewrites in Hostinger:

```
/*    /index.html   200
```

---

## 🔐 Security Notes

1. **Never commit `.env` files** - They're in `.gitignore`
2. **Use strong JWT secrets** - 64+ characters
3. **Use HTTPS** - Hostinger provides free SSL
4. **Secure your MongoDB** - Whitelist only necessary IPs

---

## 📞 Support

If you encounter issues:
1. Check Hostinger's deployment logs
2. Review browser console errors
3. Contact Hostinger 24/7 support via live chat

---

Happy deploying! 🚀
