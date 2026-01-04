# 🏠 DealDirect - Secure Real Estate Platform

[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green.svg)](./backend/SECURITY_REFACTOR.md)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node.js-18%2B-brightgreen.svg)](https://nodejs.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-6%2B-green.svg)](https://mongodb.com)

A modern, security-hardened real estate platform connecting property Owners directly with Buyers. Built with the MERN stack featuring enterprise-grade security measures.

---

## 🚀 Features

### Core Functionality
- **Property Listings** - Owners can list residential & commercial properties
- **Smart Search** - Advanced filtering, saved searches, and instant suggestions
- **Lead Management** - Comprehensive lead tracking and analytics
- **Real-time Chat** - Socket.IO powered messaging between Users and Owners
- **Agreement Generation** - AI-powered legal agreement creation with Gemini
- **Notifications** - In-app and email notifications for property matches

### Security Features 🔒
- **IDOR Protection** - All operations verify ownership from database
- **CORS Lockdown** - Strict domain whitelist, no wildcard origins
- **Rate Limiting** - Multi-tier (Auth: 5/15min, Global: 500/15min)
- **CSP Headers** - Restrictive Content Security Policy via Helmet
- **Magic Byte Validation** - File uploads verified by actual content
- **Cryptographic Signing** - Agreements protected with HMAC-SHA256
- **Secure Cookies** - HttpOnly, Secure, SameSite=Strict

---

## 📁 Project Structure

```
dealdirect/
├── backend/           # Express.js API server
│   ├── config/        # Database configuration
│   ├── controllers/   # Route handlers
│   ├── middleware/    # Auth, validation, error handling
│   ├── models/        # Mongoose schemas
│   ├── routes/        # API endpoints
│   └── utils/         # Helper functions
├── client/            # React frontend (Buyers/Users)
│   ├── src/
│   │   ├── Components/
│   │   ├── Pages/
│   │   └── utils/
├── Admin/             # React admin dashboard (Property Management)
│   ├── src/
│   │   ├── components/
│   │   └── pages/
└── README.md
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React 18, Vite, TailwindCSS |
| **Backend** | Node.js, Express 5 |
| **Database** | MongoDB with Mongoose |
| **Auth** | JWT + HttpOnly Cookies |
| **Real-time** | Socket.IO |
| **File Storage** | Cloudinary |
| **AI** | Google Gemini (Agreement generation) |
| **Security** | Helmet, express-rate-limit, hpp |

---

## ⚡ Quick Start

### Prerequisites
- Node.js 18+
- MongoDB 6+
- Cloudinary account
- (Optional) Google Gemini API key

### 1. Clone the repository
```bash
git clone https://github.com/chirag-says/DealDirectSecure.git
cd DealDirectSecure
```

### 2. Install dependencies
```bash
# Backend
cd backend && npm install

# Client
cd ../client && npm install

# Admin
cd ../Admin && npm install
```

### 3. Configure environment variables

Create `.env` files in each directory:

**backend/.env**
```env
# Required
NODE_ENV=development
PORT=9000
MONGO_URI=mongodb+srv://your-connection-string
JWT_SECRET=your-64-char-minimum-secret-key

# CORS (use your actual URLs in production)
CLIENT_URL=http://localhost:5173
ADMIN_URL=http://localhost:5174

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Email (optional)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# Security (required for production)
AGREEMENT_SECRET_KEY=your-agreement-signing-key
PAYMENT_WEBHOOK_SECRET=your-payment-gateway-secret
```

**client/.env**
```env
VITE_API_URL=http://localhost:9000/api
VITE_SOCKET_URL=http://localhost:9000
```

**Admin/.env**
```env
VITE_API_URL=http://localhost:9000/api
```

### 4. Start development servers

```bash
# Terminal 1 - Backend
cd backend && npm run dev

# Terminal 2 - Client
cd client && npm run dev

# Terminal 3 - Admin
cd Admin && npm run dev
```

| Service | URL |
|---------|-----|
| Backend API | http://localhost:9000 |
| Client | http://localhost:5173 |
| Admin | http://localhost:5174 |

---

## 🔐 Security Documentation

For detailed security implementation, see [SECURITY_REFACTOR.md](./backend/SECURITY_REFACTOR.md).

### Highlights

| Feature | Implementation |
|---------|----------------|
| **Authentication** | JWT in HttpOnly cookies, session versioning |
| **Authorization** | Role-based (Owner/Buyer), IDOR protection |
| **Input Validation** | express-validator, field whitelisting |
| **Rate Limiting** | 5 login attempts/15min, 500 global/15min |
| **File Uploads** | Magic byte verification, blocked executables |
| **Headers** | Helmet CSP, HSTS, X-Frame-Options: DENY |
| **Agreements** | Idempotency keys, HMAC signatures |
| **Error Handling** | Zero internal info leakage in production |

---

## 📡 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/users/register` | Register new user |
| POST | `/api/users/login` | Login with email/password |
| POST | `/api/users/logout` | Logout (clears cookie) |
| POST | `/api/users/forgot-password` | Request password reset |

### Properties
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/properties/list` | List all properties |
| GET | `/api/properties/search` | Search with filters |
| POST | `/api/properties/add` | Add property (Owner) |
| PUT | `/api/properties/my-properties/:id` | Update own property |
| DELETE | `/api/properties/:id` | Delete own property |

### Leads
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/leads` | Get owner's leads |
| PUT | `/api/leads/:id/status` | Update lead status |
| GET | `/api/leads/analytics` | Lead analytics |

### Agreements
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agreements/generate` | Generate agreement |
| GET | `/api/agreements/my-agreements` | User's agreements |
| POST | `/api/agreements/:id/sign` | Sign agreement |

---

## 🚀 Deployment

### Production Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Use HTTPS with valid SSL certificate
- [ ] Set strong secrets (64+ characters)
- [ ] Configure production MongoDB
- [ ] Set actual `CLIENT_URL` and `ADMIN_URL`
- [ ] Set up log aggregation
- [ ] Enable monitoring/alerting
- [ ] Review and test rate limits

### Environment Validation

The server performs pre-flight checks and **refuses to start** if:
- `JWT_SECRET` is missing or < 32 chars (production)
- `MONGO_URI` is missing
- Production mode missing `CLIENT_URL`, `ADMIN_URL`, `AGREEMENT_SECRET_KEY`

---

## 🧪 Testing

```bash
# Run backend tests
cd backend && npm test

# Run with coverage
npm run test:coverage
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📞 Support

For support, email support@dealdirect.com or open an issue.

---

## 🙏 Acknowledgments

- [Express.js](https://expressjs.com/)
- [React](https://reactjs.org/)
- [MongoDB](https://mongodb.com/)
- [Cloudinary](https://cloudinary.com/)
- [Google Gemini](https://ai.google.dev/)

---

**Built with ❤️ by Team DealDirect**
