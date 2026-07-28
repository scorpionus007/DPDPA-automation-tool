import { useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
// eslint-disable-next-line no-unused-vars
import { motion } from 'framer-motion';
import { Mail, Lock, CheckCircle2 } from 'lucide-react';
import FormInput from '../components/auth/FormInput';
import GitHubButton from '../components/auth/GitHubButton';
import { validateEmail, validateLoginPassword, sanitizeInput } from '../utils/validation';
import '../styles/auth.css';
import { API_BASE_URL } from '../utils/api';

const CARD_VARIANTS = {
  hidden: { opacity: 0, y: 16 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.45, ease: [0.25, 0.46, 0.45, 0.94] },
  },
};

export default function LoginPage() {
  // State
  const [form, setForm] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  // Handlers
  const handleChange = useCallback((field) => (e) => {
    const val = e.target.value;
    setForm((prev) => ({ ...prev, [field]: val }));
    if (errors[field]) {
      setErrors((prev) => ({ ...prev, [field]: '' }));
    }
  }, [errors]);

  const handleBlur = useCallback((field) => () => {
    setTouched((prev) => ({ ...prev, [field]: true }));
    const value = form[field];
    let error = '';
    if (field === 'email') error = validateEmail(value);
    if (field === 'password') error = validateLoginPassword(value);
    setErrors((prev) => ({ ...prev, [field]: error }));
  }, [form]);

  const runValidation = useCallback(() => {
    const next = {
      email: validateEmail(form.email),
      password: validateLoginPassword(form.password),
    };
    setErrors(next);
    setTouched({ email: true, password: true });
    return !next.email && !next.password;
  }, [form]);

  const navigate = useNavigate();

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    if (!runValidation()) return;

    setIsSubmitting(true);
    const payload = {
      email: sanitizeInput(form.email),
      password: form.password,
    };

    try {
      const response = await fetch('http://localhost:8000/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error('Invalid email or password');
      }

      const data = await response.json();
      localStorage.setItem('token', data.access_token);
      
      setSuccess(true);
      setTimeout(() => {
        navigate('/dashboard');
      }, 1500);
    } catch (err) {
      setErrors((prev) => ({
        ...prev,
        email: err.message || 'Invalid email or password',
      }));
    } finally {
      setIsSubmitting(false);
    }
  }, [form, runValidation, navigate]);

  const handleGitHubLogin = useCallback(() => {
    window.location.href = 'http://localhost:8000/auth/github/login';
  }, []);

  // Render
  return (
    <div className="auth-page">
      <div className="auth-bg" />

      <motion.div
        className="auth-card"
        variants={CARD_VARIANTS}
        initial="hidden"
        animate="visible"
      >

        <motion.div
          className="auth-heading"
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.1 }}
        >
          <h1>Welcome back</h1>
          <p>Sign in to continue to your compliance dashboard</p>
        </motion.div>

        {success ? (
          <motion.div
            className="auth-success"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: 'spring', stiffness: 300, damping: 20 }}
            style={{ marginTop: '1.5rem' }}
          >
            <CheckCircle2 />
            <span>Login successful! Redirecting…</span>
          </motion.div>
        ) : (
          <form className="auth-form" onSubmit={handleSubmit} noValidate>
            <FormInput
              id="login-email"
              label="Email address"
              type="email"
              icon={Mail}
              placeholder="you@company.com"
              value={form.email}
              onChange={handleChange('email')}
              onBlur={handleBlur('email')}
              error={touched.email ? errors.email : ''}
              autoComplete="email"
              delay={0.15}
            />

            <FormInput
              id="login-password"
              label="Password"
              type="password"
              icon={Lock}
              placeholder="Enter your password"
              value={form.password}
              onChange={handleChange('password')}
              onBlur={handleBlur('password')}
              error={touched.password ? errors.password : ''}
              autoComplete="current-password"
              delay={0.2}
            />

            <motion.div
              className="auth-forgot"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.25 }}
            >
              <a href="#" onClick={(e) => e.preventDefault()}>
                Forgot password?
              </a>
            </motion.div>

            <motion.button
              type="submit"
              className="auth-submit-btn"
              disabled={isSubmitting}
              whileHover={!isSubmitting ? { scale: 1.01 } : {}}
              whileTap={!isSubmitting ? { scale: 0.99 } : {}}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: 0.25 }}
            >
              {isSubmitting ? (
                <div className="spinner" />
              ) : (
                <span>Sign In</span>
              )}
            </motion.button>

            <motion.div
              className="auth-divider"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3 }}
            >
              <span>OR</span>
            </motion.div>

            <GitHubButton
              label="Continue with GitHub"
              onClick={handleGitHubLogin}
            />
          </form>
        )}

        <motion.div
          className="auth-footer"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}
        >
          <span>Don&apos;t have an account?</span>
          <Link to="/signup" className="auth-footer-btn">
            Create account
          </Link>
        </motion.div>
      </motion.div>
    </div>
  );
}
