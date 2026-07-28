import { useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
// eslint-disable-next-line no-unused-vars
import { motion, AnimatePresence } from 'framer-motion';
import { Mail, Lock, User, ArrowRight, CheckCircle2, Check } from 'lucide-react';
import FormInput from '../components/auth/FormInput';
import PasswordStrength from '../components/auth/PasswordStrength';
import GitHubButton from '../components/auth/GitHubButton';
import {
  validateEmail,
  validateSignupPassword,
  validateName,
  validateConfirmPassword,
  evaluatePasswordStrength,
  sanitizeInput,
} from '../utils/validation';
import '../styles/auth.css';

const CARD_VARIANTS = {
  hidden: { opacity: 0, y: 16 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.45, ease: [0.25, 0.46, 0.45, 0.94] },
  },
};

export default function SignupPage() {
  /* ---------- State ---------- */
  const [form, setForm] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});
  const [agreed, setAgreed] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  /* Password strength derived state */
  const passwordStrength = evaluatePasswordStrength(form.password);

  /* ---------- Handlers ---------- */
  const handleChange = useCallback((field) => (e) => {
    const val = e.target.value;
    setForm((prev) => ({ ...prev, [field]: val }));
    if (errors[field]) {
      setErrors((prev) => ({ ...prev, [field]: '' }));
    }
  }, [errors]);

  const handleBlur = useCallback((field) => () => {
    setTouched((prev) => ({ ...prev, [field]: true }));
    let error = '';
    switch (field) {
      case 'name':
        error = validateName(form.name);
        break;
      case 'email':
        error = validateEmail(form.email);
        break;
      case 'password':
        error = validateSignupPassword(form.password);
        break;
      case 'confirmPassword':
        error = validateConfirmPassword(form.password, form.confirmPassword);
        break;
    }
    setErrors((prev) => ({ ...prev, [field]: error }));
  }, [form]);

  const runValidation = useCallback(() => {
    const next = {
      name: validateName(form.name),
      email: validateEmail(form.email),
      password: validateSignupPassword(form.password),
      confirmPassword: validateConfirmPassword(form.password, form.confirmPassword),
    };
    setErrors(next);
    setTouched({ name: true, email: true, password: true, confirmPassword: true });
    return !next.name && !next.email && !next.password && !next.confirmPassword;
  }, [form]);

  const navigate = useNavigate();

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    if (!runValidation()) return;
    if (!agreed) {
      setErrors((prev) => ({
        ...prev,
        terms: 'You must agree to the terms',
      }));
      return;
    }

    setIsSubmitting(true);
    const payload = {
      username: sanitizeInput(form.name), // map name to username
      email: sanitizeInput(form.email),
      password: form.password, // never trim passwords
    };

    try {
      const response = await fetch('http://localhost:8000/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Signup failed');
      }

      setSuccess(true);
      setTimeout(() => {
        navigate('/dashboard');
      }, 1500);
    } catch (err) {
      setErrors((prev) => ({
        ...prev,
        email: err.message || 'An account with this email already exists',
      }));
    } finally {
      setIsSubmitting(false);
    }
  }, [form, agreed, runValidation, navigate]);

  const handleGitHubLogin = useCallback(() => {
    window.location.href = 'http://localhost:8000/auth/github/login';
  }, []);

  /* ---------- Render ---------- */
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
          <h1>Create your account</h1>
          <p>Start scanning your codebase for DPDP compliance</p>
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
            <span>Account created! Redirecting to dashboard…</span>
          </motion.div>
        ) : (
          <form className="auth-form" onSubmit={handleSubmit} noValidate>
            <FormInput
              id="signup-name"
              label="Full name"
              type="text"
              icon={User}
              placeholder="John Doe"
              value={form.name}
              onChange={handleChange('name')}
              onBlur={handleBlur('name')}
              error={touched.name ? errors.name : ''}
              autoComplete="name"
              delay={0.15}
            />

            <FormInput
              id="signup-email"
              label="Email address"
              type="email"
              icon={Mail}
              placeholder="you@company.com"
              value={form.email}
              onChange={handleChange('email')}
              onBlur={handleBlur('email')}
              error={touched.email ? errors.email : ''}
              autoComplete="email"
              delay={0.2}
            />

            <div>
              <FormInput
                id="signup-password"
                label="Password"
                type="password"
                icon={Lock}
                placeholder="Create a strong password"
                value={form.password}
                onChange={handleChange('password')}
                onBlur={handleBlur('password')}
                error={touched.password ? errors.password : ''}
                autoComplete="new-password"
                delay={0.25}
              />
              <AnimatePresence>
                {form.password && (
                  <PasswordStrength
                    score={passwordStrength.score}
                    label={passwordStrength.label}
                  />
                )}
              </AnimatePresence>
            </div>

            <FormInput
              id="signup-confirm-password"
              label="Confirm password"
              type="password"
              icon={Lock}
              placeholder="Re-enter your password"
              value={form.confirmPassword}
              onChange={handleChange('confirmPassword')}
              onBlur={handleBlur('confirmPassword')}
              error={touched.confirmPassword ? errors.confirmPassword : ''}
              autoComplete="new-password"
              delay={0.3}
            />

            {/* Terms checkbox */}
            <motion.label
              className="auth-checkbox"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.35 }}
            >
              <input
                type="checkbox"
                checked={agreed}
                onChange={(e) => {
                  setAgreed(e.target.checked);
                  if (errors.terms) setErrors((prev) => ({ ...prev, terms: '' }));
                }}
              />
              <span className="auth-checkbox-box">
                <Check />
              </span>
              <span className="auth-checkbox-label">
                I agree to the{' '}
                <a href="#" onClick={(e) => e.preventDefault()}>Terms of Service</a>
                {' '}and{' '}
                <a href="#" onClick={(e) => e.preventDefault()}>Privacy Policy</a>
              </span>
            </motion.label>

            {errors.terms && (
              <motion.div
                className="input-error"
                role="alert"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
              >
                <span>{errors.terms}</span>
              </motion.div>
            )}

            <motion.button
              type="submit"
              className="auth-submit-btn"
              disabled={isSubmitting}
              whileHover={!isSubmitting ? { scale: 1.01 } : {}}
              whileTap={!isSubmitting ? { scale: 0.99 } : {}}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: 0.4 }}
            >
              {isSubmitting ? (
                <div className="spinner" />
              ) : (
                <>
                  <span>Create Account</span>
                </>
              )}
            </motion.button>

            <motion.div
              className="auth-divider"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.45 }}
            >
              <span>OR</span>
            </motion.div>

            <GitHubButton
              label="Sign up with GitHub"
              onClick={handleGitHubLogin}
            />
          </form>
        )}

        <motion.div
          className="auth-footer"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.45 }}
        >
          Already have an account?{' '}
          <Link to="/login" className="auth-footer-link">Log in</Link>
        </motion.div>
      </motion.div>
    </div>
  );
}
