import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import toast from 'react-hot-toast';
import { useAuth } from '../contexts/AuthContext';
import { cryptoService } from '../services/crypto';

interface LoginForm {
  email: string;
}

const schema = yup.object({
  email: yup.string().email('Invalid email address').required('Email is required'),
}).required();

const Authentication: React.FC = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [isSigning, setIsSigning] = useState(false);
  const [challengeReceived, setChallengeReceived] = useState(false);
  const [challengeId, setChallengeId] = useState<string>('');
  const [challengeNonce, setChallengeNonce] = useState<string>('');
  const navigate = useNavigate();
  const { login, verifyChallenge } = useAuth();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginForm>({
    resolver: yupResolver(schema),
  });

  const onSubmit = async (data: LoginForm) => {
    setIsLoading(true);

    try {
      toast.loading('Initiating authentication...', { id: 'login' });

      const success = await login(data.email);

      if (success) {
        // Get challenge data from localStorage (set by auth context)
        const storedChallengeId = localStorage.getItem('challengeId');
        const storedNonce = localStorage.getItem('challengeNonce');

        if (storedChallengeId && storedNonce) {
          setChallengeId(storedChallengeId);
          setChallengeNonce(storedNonce);
          setChallengeReceived(true);
          toast.success('Challenge received! Please sign with your private key.', { id: 'login' });
        } else {
          toast.error('Failed to receive challenge. Please try again.', { id: 'login' });
        }
      } else {
        toast.error('User not found. Please check your email or register.', { id: 'login' });
      }
    } catch (error) {
      console.error('Login error:', error);
      toast.error('Authentication failed. Please try again.', { id: 'login' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSignChallenge = async () => {
    setIsSigning(true);

    try {
      toast.loading('Signing challenge...', { id: 'sign' });

      // Get private key from localStorage
      const privateKeyPem = localStorage.getItem('privateKey');
      if (!privateKeyPem) {
        toast.error('Private key not found. Please register again.', { id: 'sign' });
        return;
      }

      // Sign the challenge
      const signature = await cryptoService.signChallenge(privateKeyPem, challengeNonce);

      toast.success('Challenge signed!', { id: 'sign' });
      toast.loading('Verifying signature...', { id: 'verify' });

      // Verify the signature
      const success = await verifyChallenge(challengeId, signature);

      if (success) {
        toast.success('Authentication successful!', { id: 'verify' });
        navigate('/dashboard');
      } else {
        toast.error('Signature verification failed. Please try again.', { id: 'verify' });
      }
    } catch (error) {
      console.error('Signing error:', error);
      toast.error('Failed to sign challenge. Please try again.', { id: 'sign' });
    } finally {
      setIsSigning(false);
    }
  };

  const handleBackToEmail = () => {
    setChallengeReceived(false);
    setChallengeId('');
    setChallengeNonce('');
    localStorage.removeItem('challengeId');
    localStorage.removeItem('challengeNonce');
  };

  if (challengeReceived) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h1 className="auth-title">Sign Challenge</h1>
          <p className="auth-subtitle">
            Use your private key to sign the authentication challenge
          </p>

          <div className="challenge-info">
            <p>Challenge received from server. Click the button below to sign it with your private key.</p>
            <div className="challenge-details">
              <small>Challenge ID: {challengeId.substring(0, 8)}...</small>
            </div>
          </div>

          <button
            onClick={handleSignChallenge}
            className="btn btn-primary"
            disabled={isSigning}
          >
            {isSigning ? (
              <>
                <span className="loading-spinner"></span>
                Signing Challenge...
              </>
            ) : (
              'Sign Challenge'
            )}
          </button>

          <button
            onClick={handleBackToEmail}
            className="btn btn-secondary"
            disabled={isSigning}
          >
            Back to Email
          </button>

          <div className="security-info">
            <h3>What's happening:</h3>
            <ul>
              <li>✓ Server sent a unique challenge</li>
              <li>✓ Your device will sign it with your private key</li>
              <li>✓ Only you can create this signature</li>
              <li>✓ Server verifies the signature with your public key</li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h1 className="auth-title">Sign In</h1>
        <p className="auth-subtitle">
          Enter your email to receive an authentication challenge
        </p>

        <form onSubmit={handleSubmit(onSubmit)}>
          <div className="form-group">
            <label htmlFor="email" className="form-label">
              Email Address
            </label>
            <input
              id="email"
              type="email"
              className={`form-input ${errors.email ? 'error' : ''}`}
              placeholder="Enter your email"
              {...register('email')}
            />
            {errors.email && <span className="error-message">{errors.email.message}</span>}
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <span className="loading-spinner"></span>
                Requesting Challenge...
              </>
            ) : (
              'Request Challenge'
            )}
          </button>
        </form>

        <div className="auth-footer">
          Don't have an account?{' '}
          <Link to="/register" className="auth-link">
            Create one
          </Link>
        </div>

        <div className="security-info">
          <h3>How it works:</h3>
          <ul>
            <li>✓ Enter your email address</li>
            <li>✓ Server sends a unique challenge</li>
            <li>✓ Your device signs it with your private key</li>
            <li>✓ Server verifies your identity</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Authentication; 