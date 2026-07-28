/* eslint-disable no-unused-vars */
import { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Eye, EyeOff, AlertCircle } from 'lucide-react';

/**
 * Styled input with icon, label, error display, and optional password toggle.
 * Supports `labelExtra` for rendering additional content next to the label (e.g. "Forgot password?").
 */
export default function FormInput({
  id,
  label,
  labelExtra,
  type = 'text',
  icon: Icon,
  placeholder,
  value,
  onChange,
  onBlur,
  error,
  name,
  autoComplete,
  required = true,
  delay = 0,
}) {
  const [showPassword, setShowPassword] = useState(false);
  const isPasswordField = type === 'password';

  const togglePassword = useCallback(() => {
    setShowPassword((prev) => !prev);
  }, []);

  const inputType = isPasswordField ? (showPassword ? 'text' : 'password') : type;

  return (
    <motion.div
      className="input-group"
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay }}
    >
      {(label || labelExtra) && (
        <div className="label-row">
          {label && <label htmlFor={id}>{label}</label>}
          {labelExtra && labelExtra}
        </div>
      )}
      <div className="input-wrapper">
        {Icon && <Icon className="input-icon" />}
        <input
          id={id}
          name={name || id}
          type={inputType}
          placeholder={placeholder}
          value={value}
          onChange={onChange}
          onBlur={onBlur}
          autoComplete={autoComplete}
          required={required}
          aria-invalid={!!error}
          aria-describedby={error ? `${id}-error` : undefined}
        />
        {isPasswordField && (
          <button
            type="button"
            className="input-toggle"
            onClick={togglePassword}
            tabIndex={-1}
            aria-label={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? <EyeOff /> : <Eye />}
          </button>
        )}
      </div>
      <AnimatePresence mode="wait">
        {error && (
          <motion.div
            id={`${id}-error`}
            className="input-error"
            role="alert"
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.2 }}
          >
            <AlertCircle />
            <span>{error}</span>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
