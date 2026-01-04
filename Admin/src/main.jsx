import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import axios from 'axios'
import './index.css'
import App from './App.jsx'
import { ToastContainer } from 'react-toastify'
import "react-toastify/dist/ReactToastify.css";

// CRITICAL: Configure axios globally to send cookies with all requests
// This ensures HttpOnly session cookies are sent automatically
axios.defaults.withCredentials = true;
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
    <ToastContainer position="top-right" autoClose={3000} />
  </StrictMode>,
)
