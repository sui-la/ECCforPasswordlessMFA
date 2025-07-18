import axios from 'axios';

// Create axios instance with default configuration
export const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('sessionToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle common errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      // Unauthorized - clear session
      localStorage.removeItem('sessionToken');
      localStorage.removeItem('privateKey');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// API endpoints
export const authAPI = {
  // Registration
  register: (data: { email: string; name?: string; public_key: string }) =>
    api.post('/api/auth/register', data),
  
  checkEmailAvailability: (email: string) =>
    api.post('/api/auth/register/check-email', { email }),
  
  generateRegistrationChallenge: (email: string) =>
    api.post('/api/auth/register/challenge', { email }),
  
  verifyRegistration: (data: { email: string; nonce: string; signature: string }) =>
    api.post('/api/auth/register/verify', data),
  
  // Authentication
  initiateLogin: (email: string) =>
    api.post('/api/auth/login/initiate', { email }),
  
  verifyLogin: (data: { challenge_id: string; signature: string }) =>
    api.post('/api/auth/login/verify', data),
  
  logout: (sessionToken: string) =>
    api.post('/api/auth/logout', { session_token: sessionToken }),
  
  validateSession: (sessionToken: string) =>
    api.post('/api/auth/session/validate', { session_token: sessionToken }),
  
  refreshSession: (sessionToken: string) =>
    api.post('/api/auth/session/refresh', { session_token: sessionToken }),
  
  // Secure session
  establishSecureSession: (data: { user_id: string; client_public_key: string }) =>
    api.post('/api/auth/secure-session/establish', data),
};

export const userAPI = {
  getProfile: () => api.get('/api/user/profile'),
  
  getSessions: () => api.get('/api/user/sessions'),
  
  invalidateAllSessions: () => api.post('/api/user/sessions/invalidate-all'),
};

export const healthAPI = {
  check: () => api.get('/health'),
}; 