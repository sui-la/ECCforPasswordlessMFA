import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { api } from '../services/api';
import { cryptoService } from '../services/crypto';

interface User {
  user_id: string;
  email: string;
  name?: string;
  created_at: string;
  last_login?: string;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  sessionToken: string | null;
  login: (email: string) => Promise<boolean>;
  logout: () => void;
  register: (email: string, name?: string) => Promise<boolean>;
  verifyChallenge: (challengeId: string, signature: string) => Promise<boolean>;
  checkEmailAvailability: (email: string) => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Check for existing session on app load
  useEffect(() => {
    const token = localStorage.getItem('sessionToken');
    if (token) {
      validateSession(token);
    }
  }, []);

  const validateSession = async (token: string) => {
    try {
      const response = await api.post('/api/auth/session/validate', {
        session_token: token
      });

      if (response.data.success) {
        setUser(response.data);
        setSessionToken(token);
        setIsAuthenticated(true);
      } else {
        // Invalid session, clear storage
        localStorage.removeItem('sessionToken');
        setUser(null);
        setSessionToken(null);
        setIsAuthenticated(false);
      }
    } catch (error) {
      console.error('Session validation error:', error);
      localStorage.removeItem('sessionToken');
      setUser(null);
      setSessionToken(null);
      setIsAuthenticated(false);
    }
  };

  const login = async (email: string): Promise<boolean> => {
    try {
      const response = await api.post('/api/auth/login/initiate', { email });
      
      if (response.data.success) {
        // Store challenge info for verification
        localStorage.setItem('challengeId', response.data.challenge_id);
        localStorage.setItem('challengeNonce', response.data.nonce);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Login initiation error:', error);
      return false;
    }
  };

  const verifyChallenge = async (challengeId: string, signature: string): Promise<boolean> => {
    try {
      const response = await api.post('/api/auth/login/verify', {
        challenge_id: challengeId,
        signature: signature
      });

      if (response.data.success) {
        setUser(response.data);
        setSessionToken(response.data.session_token);
        setIsAuthenticated(true);
        localStorage.setItem('sessionToken', response.data.session_token);
        
        // Clear challenge data
        localStorage.removeItem('challengeId');
        localStorage.removeItem('challengeNonce');
        
        return true;
      }
      return false;
    } catch (error) {
      console.error('Challenge verification error:', error);
      return false;
    }
  };

  const register = async (email: string, name?: string): Promise<boolean> => {
    try {
      // Generate ECC keypair
      const keyPair = await cryptoService.generateKeyPair();
      
      const response = await api.post('/api/auth/register', {
        email,
        name,
        public_key: keyPair.publicKeyPem
      });

      if (response.data.success) {
        // Store private key securely (in production, use secure storage)
        localStorage.setItem('privateKey', keyPair.privateKeyPem);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Registration error:', error);
      return false;
    }
  };

  const logout = async () => {
    try {
      if (sessionToken) {
        await api.post('/api/auth/logout', {
          session_token: sessionToken
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear all auth data
      localStorage.removeItem('sessionToken');
      localStorage.removeItem('privateKey');
      localStorage.removeItem('challengeId');
      localStorage.removeItem('challengeNonce');
      
      setUser(null);
      setSessionToken(null);
      setIsAuthenticated(false);
    }
  };

  const checkEmailAvailability = async (email: string): Promise<boolean> => {
    try {
      const response = await api.post('/api/auth/register/check-email', { email });
      return response.data.success && response.data.available;
    } catch (error) {
      console.error('Email availability check error:', error);
      return false;
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated,
    sessionToken,
    login,
    logout,
    register,
    verifyChallenge,
    checkEmailAvailability
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}; 