import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import toast from 'react-hot-toast';
import { useAuth } from '../contexts/AuthContext';
import { cryptoService } from '../services/crypto';

interface RegistrationForm {
  email: string;
  name: string;
}

const schema = yup.object({
  email: yup.string().email('Invalid email address').required('Email is required'),
  name: yup.string().min(2, 'Name must be at least 2 characters').required('Name is required'),
}).required();

const Registration: React.FC = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [emailAvailable, setEmailAvailable] = useState<boolean | null>(null);
  const navigate = useNavigate();
  const { register: registerUser, checkEmailAvailability } = useAuth();

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<RegistrationForm>({
    resolver: yupResolver(schema),
  });

  const watchedEmail = watch('email');

  // Check email availability when email changes
  React.useEffect(() => {
    const checkEmail = async () => {
      if (watchedEmail && watchedEmail.includes('@')) {
        try {
          const available = await checkEmailAvailability(watchedEmail);
          setEmailAvailable(available);
        } catch (error) {
          setEmailAvailable(null);
        }
      } else {
        setEmailAvailable(null);
      }
    };

    const timeoutId = setTimeout(checkEmail, 500);
    return () => clearTimeout(timeoutId);
  }, [watchedEmail, checkEmailAvailability]);

  const onSubmit = async (data: RegistrationForm) => {
    if (emailAvailable === false) {
      toast.error('Email is already registered');
      return;
    }

    setIsLoading(true);
    setIsGeneratingKeys(true);

    try {
      // Show key generation progress
      toast.loading('Generating cryptographic keys...', { id: 'keygen' });

      // Generate ECC key pair
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const keyPair = await cryptoService.generateKeyPair();

      toast.success('Keys generated successfully!', { id: 'keygen' });
      toast.loading('Registering account...', { id: 'register' });

      // Register user with public key
      const success = await registerUser(data.email, data.name);

      if (success) {
        toast.success('Registration successful!', { id: 'register' });
        toast.success('Your private key has been saved securely. Please keep it safe!', {
          duration: 6000,
        });
        navigate('/login');
      } else {
        toast.error('Registration failed. Please try again.', { id: 'register' });
      }
    } catch (error) {
      console.error('Registration error:', error);
      toast.error('Registration failed. Please try again.', { id: 'register' });
      toast.error('Key generation failed. Please try again.', { id: 'keygen' });
    } finally {
      setIsLoading(false);
      setIsGeneratingKeys(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h1 className="auth-title">Create Account</h1>
        <p className="auth-subtitle">
          Register with ECC-based passwordless authentication
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
            {emailAvailable === true && (
              <span className="success-message">✓ Email is available</span>
            )}
            {emailAvailable === false && (
              <span className="error-message">✗ Email is already registered</span>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="name" className="form-label">
              Full Name
            </label>
            <input
              id="name"
              type="text"
              className={`form-input ${errors.name ? 'error' : ''}`}
              placeholder="Enter your full name"
              {...register('name')}
            />
            {errors.name && <span className="error-message">{errors.name.message}</span>}
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={isLoading || emailAvailable === false}
          >
            {isLoading ? (
              <>
                <span className="loading-spinner"></span>
                {isGeneratingKeys ? 'Generating Keys...' : 'Creating Account...'}
              </>
            ) : (
              'Create Account'
            )}
          </button>
        </form>

        <div className="auth-footer">
          Already have an account?{' '}
          <Link to="/login" className="auth-link">
            Sign in
          </Link>
        </div>

        <div className="security-info">
          <h3>How it works:</h3>
          <ul>
            <li>✓ Your device generates a unique cryptographic key pair</li>
            <li>✓ Only the public key is sent to our servers</li>
            <li>✓ Your private key stays secure on your device</li>
            <li>✓ No passwords to remember or manage</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Registration; 