import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuth } from '../contexts/AuthContext';
import { userAPI } from '../services/api';

interface Session {
  session_id: string;
  created_at: string;
  expires_at: string;
  ip_address: string;
  user_agent: string;
  is_active: boolean;
}

const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadUserData();
  }, []);

  const loadUserData = async () => {
    try {
      const response = await userAPI.getSessions();
      if (response.data.success) {
        setSessions(response.data.sessions);
      }
    } catch (error) {
      console.error('Error loading user data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      toast.success('Logged out successfully');
    } catch (error) {
      console.error('Logout error:', error);
      toast.error('Logout failed');
    }
  };

  const handleInvalidateAllSessions = async () => {
    try {
      const response = await userAPI.invalidateAllSessions();
      if (response.data.success) {
        toast.success(`Invalidated ${response.data.invalidated_count} sessions`);
        loadUserData(); // Reload sessions
      }
    } catch (error) {
      console.error('Error invalidating sessions:', error);
      toast.error('Failed to invalidate sessions');
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getSessionStatus = (session: Session) => {
    if (!session.is_active) return 'Inactive';
    if (new Date(session.expires_at) < new Date()) return 'Expired';
    return 'Active';
  };

  if (isLoading) {
    return (
      <div className="dashboard-container">
        <div className="loading-spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <nav className="navbar">
        <div className="navbar-brand">ECC MFA Dashboard</div>
        <ul className="navbar-nav">
          <li>
            <Link to="/dashboard" className="nav-link active">
              Dashboard
            </Link>
          </li>
          <li>
            <Link to="/keys" className="nav-link">
              Key Management
            </Link>
          </li>
          <li>
            <button onClick={handleLogout} className="nav-link btn-link">
              Logout
            </button>
          </li>
        </ul>
      </nav>

      <div className="dashboard-header">
        <h1 className="dashboard-title">Welcome, {user?.name || user?.email}!</h1>
        <p className="dashboard-subtitle">
          Your ECC-based passwordless authentication dashboard
        </p>
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-card">
          <h2 className="card-title">Account Information</h2>
          <div className="card-content">
            <p><strong>Email:</strong> {user?.email}</p>
            <p><strong>Name:</strong> {user?.name || 'Not provided'}</p>
            <p><strong>Member since:</strong> {formatDate(user?.created_at || '')}</p>
            <p><strong>Last login:</strong> {user?.last_login ? formatDate(user.last_login) : 'Never'}</p>
          </div>
        </div>

        <div className="dashboard-card">
          <h2 className="card-title">Security Status</h2>
          <div className="card-content">
            <div className="status-item">
              <span className="status-indicator status-success"></span>
              <span>ECC Authentication Active</span>
            </div>
            <div className="status-item">
              <span className="status-indicator status-success"></span>
              <span>Private Key Secured</span>
            </div>
            <div className="status-item">
              <span className="status-indicator status-info"></span>
              <span>Session Valid</span>
            </div>
          </div>
        </div>

        <div className="dashboard-card">
          <h2 className="card-title">Active Sessions</h2>
          <div className="card-content">
            <p><strong>Total sessions:</strong> {sessions.length}</p>
            <p><strong>Active sessions:</strong> {sessions.filter(s => getSessionStatus(s) === 'Active').length}</p>
            <button
              onClick={handleInvalidateAllSessions}
              className="btn btn-danger"
              style={{ width: 'auto', marginTop: '10px' }}
            >
              Invalidate All Other Sessions
            </button>
          </div>
        </div>
      </div>

      <div className="dashboard-card">
        <h2 className="card-title">Recent Sessions</h2>
        <div className="card-content">
          {sessions.length === 0 ? (
            <p>No sessions found.</p>
          ) : (
            <div className="sessions-list">
              {sessions.slice(0, 5).map((session) => (
                <div key={session.session_id} className="session-item">
                  <div className="session-info">
                    <span className="session-status">{getSessionStatus(session)}</span>
                    <span className="session-date">{formatDate(session.created_at)}</span>
                  </div>
                  <div className="session-details">
                    <small>IP: {session.ip_address}</small>
                    <small>Expires: {formatDate(session.expires_at)}</small>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="dashboard-card">
        <h2 className="card-title">Security Features</h2>
        <div className="card-content">
          <ul>
            <li>✓ Elliptic Curve Cryptography (ECC) for authentication</li>
            <li>✓ Challenge-response protocol prevents replay attacks</li>
            <li>✓ Private keys never leave your device</li>
            <li>✓ No passwords to remember or manage</li>
            <li>✓ Session management and monitoring</li>
            <li>✓ Secure key storage using Web Crypto API</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Dashboard; 