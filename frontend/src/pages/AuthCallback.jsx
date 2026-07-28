import { useEffect, useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
// eslint-disable-next-line no-unused-vars
import { motion } from 'framer-motion';
import { Loader2, AlertCircle, ArrowLeft } from 'lucide-react';

export default function AuthCallback() {
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const token = params.get('token');
    const errorCode = params.get('error');
    const redirectUrl = params.get('redirect') || '/dashboard';

    if (errorCode) {
      if (errorCode === 'github_already_linked') {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setError('This GitHub account is already connected to another user. Please use a different GitHub account or contact support.');
      } else {
        setError('An error occurred during authentication. Please try again.');
      }
      return;
    }

    if (token) {
      localStorage.setItem('token', token);
      setTimeout(() => {
        navigate(redirectUrl);
      }, 1000);
    } else {
      console.error('No token found in callback');
      navigate('/login');
    }
  }, [location, navigate]);

  return (
    <div className="auth-page" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div className="auth-bg" />
      <motion.div 
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        className="auth-card" 
        style={{ textAlign: 'center', padding: '3rem', maxWidth: '450px' }}
      >
        {!error ? (
          <>
            <Loader2 className="spinner" style={{ width: '3rem', height: '3rem', margin: '0 auto 1.5rem', color: 'var(--primary)' }} />
            <h1>Authenticating...</h1>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
              Completing your secure login through GitHub.
            </p>
          </>
        ) : (
          <>
            <div style={{ background: '#fef2f2', padding: '1.5rem', borderRadius: '12px', marginBottom: '1.5rem' }}>
              <AlertCircle size={48} color="#ef4444" style={{ margin: '0 auto 1rem' }} />
              <h2 style={{ color: '#991b1b', fontSize: '1.25rem', marginBottom: '0.5rem' }}>Auth Failed</h2>
              <p style={{ color: '#b91c1c', fontSize: '0.9rem', lineHeight: '1.5' }}>
                {error}
              </p>
            </div>
            <Link to="/login" className="btn-primary" style={{ display: 'flex', justifyContent: 'center', width: '100%' }}>
              <ArrowLeft size={18} />
              Return to Login
            </Link>
          </>
        )}
      </motion.div>
    </div>
  );
}
