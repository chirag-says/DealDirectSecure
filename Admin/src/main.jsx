import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import axios from 'axios'
// Self-hosted so the panel does not make a request to Google's CDN on every
// cold load. The variable build is one file for every weight we use.
import '@fontsource-variable/inter'
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
