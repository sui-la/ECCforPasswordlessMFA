import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuth } from '../contexts/AuthContext';
import { cryptoService } from '../services/crypto';

const KeyManagement: React.FC = () => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { user } = useAuth();
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [isGeneratingNewKeys, setIsGeneratingNewKeys] = useState(false);

  const privateKey = localStorage.getItem('privateKey');

  const handleGenerateNewKeys = async () => {
    // eslint-disable-next-line no-restricted-globals
    if (!confirm('This will generate new keys and invalidate your current ones. Continue?')) {
      return;
    }

    setIsGeneratingNewKeys(true);

    try {
      toast.loading('Generating new key pair...', { id: 'newkeys' });

      // Generate new key pair
      const newKeyPair = await cryptoService.generateKeyPair();

      // Store new private key
      localStorage.setItem('privateKey', newKeyPair.privateKeyPem);

      toast.success('New keys generated!', { id: 'newkeys' });
      toast.success('Please update your public key on the server.', {
        duration: 6000,
      });

      // In a real application, you would update the public key on the server
      // For now, we'll just show a message
      setShowPrivateKey(true);
    } catch (error) {
      console.error('Error generating new keys:', error);
      toast.error('Failed to generate new keys. Please try again.', { id: 'newkeys' });
    } finally {
      setIsGeneratingNewKeys(false);
    }
  };

  const handleExportPrivateKey = () => {
    if (!privateKey) {
      toast.error('No private key found');
      return;
    }

    const blob = new Blob([privateKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'private-key.pem';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast.success('Private key exported successfully');
  };

  const handleImportPrivateKey = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const importedKey = e.target?.result as string;
        
        // Validate the key format
        if (!importedKey.includes('-----BEGIN PRIVATE KEY-----')) {
          toast.error('Invalid private key format');
          return;
        }

        // Test the key by importing it
        await cryptoService.importPrivateKey(importedKey);
        
        // Store the key
        localStorage.setItem('privateKey', importedKey);
        toast.success('Private key imported successfully');
      } catch (error) {
        console.error('Error importing private key:', error);
        toast.error('Failed to import private key. Please check the format.');
      }
    };
    reader.readAsText(file);
  };

  const handleDeletePrivateKey = () => {
    // eslint-disable-next-line no-restricted-globals
    if (!confirm('This will delete your private key. You will need to register again. Continue?')) {
      return;
    }

    localStorage.removeItem('privateKey');
    toast.success('Private key deleted');
    setShowPrivateKey(false);
  };

  return (
    <div className="dashboard-container">
      <nav className="navbar">
        <div className="navbar-brand">ECC MFA Dashboard</div>
        <ul className="navbar-nav">
          <li>
            <Link to="/dashboard" className="nav-link">
              Dashboard
            </Link>
          </li>
          <li>
            <Link to="/keys" className="nav-link active">
              Key Management
            </Link>
          </li>
        </ul>
      </nav>

      <div className="dashboard-header">
        <h1 className="dashboard-title">Key Management</h1>
        <p className="dashboard-subtitle">
          Manage your cryptographic keys for ECC authentication
        </p>
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-card">
          <h2 className="card-title">Private Key Status</h2>
          <div className="card-content">
            <div className="status-item">
              <span className={`status-indicator ${privateKey ? 'status-success' : 'status-error'}`}></span>
              <span>{privateKey ? 'Private Key Available' : 'No Private Key Found'}</span>
            </div>
            
            {privateKey && (
              <div className="key-actions">
                <button
                  onClick={() => setShowPrivateKey(!showPrivateKey)}
                  className="btn btn-secondary"
                  style={{ width: 'auto', marginRight: '10px' }}
                >
                  {showPrivateKey ? 'Hide' : 'Show'} Private Key
                </button>
                
                <button
                  onClick={handleExportPrivateKey}
                  className="btn btn-primary"
                  style={{ width: 'auto', marginRight: '10px' }}
                >
                  Export Key
                </button>
                
                <button
                  onClick={handleDeletePrivateKey}
                  className="btn btn-danger"
                  style={{ width: 'auto' }}
                >
                  Delete Key
                </button>
              </div>
            )}

            {showPrivateKey && privateKey && (
              <div className="private-key-display">
                <h3>Your Private Key (Keep this secure!)</h3>
                <textarea
                  value={privateKey}
                  readOnly
                  className="key-textarea"
                  rows={10}
                />
                <p className="warning-text">
                  ⚠️ Never share your private key with anyone!
                </p>
              </div>
            )}
          </div>
        </div>

        <div className="dashboard-card">
          <h2 className="card-title">Key Operations</h2>
          <div className="card-content">
            <div className="operation-item">
              <h3>Generate New Keys</h3>
              <p>Create a new key pair (will invalidate current keys)</p>
              <button
                onClick={handleGenerateNewKeys}
                className="btn btn-primary"
                disabled={isGeneratingNewKeys}
              >
                {isGeneratingNewKeys ? (
                  <>
                    <span className="loading-spinner"></span>
                    Generating...
                  </>
                ) : (
                  'Generate New Keys'
                )}
              </button>
            </div>

            <div className="operation-item">
              <h3>Import Private Key</h3>
              <p>Import a private key from a file</p>
              <input
                type="file"
                accept=".pem,.txt"
                onChange={handleImportPrivateKey}
                style={{ display: 'none' }}
                id="import-key"
              />
              <label htmlFor="import-key" className="btn btn-secondary">
                Choose File
              </label>
            </div>
          </div>
        </div>

        <div className="dashboard-card">
          <h2 className="card-title">Security Information</h2>
          <div className="card-content">
            <h3>About Your Keys</h3>
            <ul>
              <li>✓ Private key is stored locally on your device</li>
              <li>✓ Never transmitted to our servers</li>
              <li>✓ Used to sign authentication challenges</li>
              <li>✓ Based on Elliptic Curve Cryptography (P-256)</li>
            </ul>

            <h3>Security Best Practices</h3>
            <ul>
              <li>🔒 Keep your private key secure and private</li>
              <li>🔒 Back up your private key safely</li>
              <li>🔒 Don't share your private key with anyone</li>
              <li>🔒 Use different keys for different services</li>
              <li>🔒 Regularly rotate your keys</li>
            </ul>
          </div>
        </div>

        <div className="dashboard-card">
          <h2 className="card-title">Key Recovery</h2>
          <div className="card-content">
            <p>
              If you lose your private key, you will need to register again with a new key pair.
              There is no way to recover a lost private key.
            </p>
            
            <div className="recovery-options">
              <h3>Recovery Options:</h3>
              <ul>
                <li>✓ Export and backup your private key</li>
                <li>✓ Store it in a secure password manager</li>
                <li>✓ Use hardware security modules (HSM) for production</li>
                <li>✓ Consider multiple key pairs for redundancy</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default KeyManagement; 