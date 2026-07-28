/**
 * Auth form validation utilities.
 * All validation is done client-side for UX; repeat on the server.
 */

/**
 * Sanitize input: trim and remove dangerous characters for XSS prevention.
 * This is a defence-in-depth measure — the server MUST also sanitize.
 */
export function sanitizeInput(value) {
  if (typeof value !== 'string') return '';
  return value.trim();
}

/**
 * Email validation using a strict but practical regex.
 */
export function validateEmail(email) {
  const cleaned = sanitizeInput(email);
  if (!cleaned) return 'Email is required';
  // RFC 5322-ish pattern; avoids catastrophic backtracking
  const pattern = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!pattern.test(cleaned)) return 'Please enter a valid email address';
  if (cleaned.length > 254) return 'Email address is too long';
  return '';
}

/**
 * Password strength scoring.
 * Returns { score: 0-4, label: string, errors: string[] }
 */
export function evaluatePasswordStrength(password) {
  const errors = [];
  let score = 0;

  if (!password) return { score: 0, label: '', errors: ['Password is required'] };
  if (password.length < 8) errors.push('At least 8 characters');
  else score++;

  if (/[A-Z]/.test(password)) score++;
  else errors.push('At least one uppercase letter');

  if (/[0-9]/.test(password)) score++;
  else errors.push('At least one number');

  if (/[^A-Za-z0-9]/.test(password)) score++;
  else errors.push('At least one special character');

  const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  return {
    score,
    label: labels[score] || '',
    errors,
  };
}

/**
 * Password validation for login (just non-empty).
 */
export function validateLoginPassword(password) {
  if (!password) return 'Password is required';
  return '';
}

/**
 * Password validation for signup.
 */
export function validateSignupPassword(password) {
  const { errors } = evaluatePasswordStrength(password);
  return errors.length > 0 ? errors[0] : '';
}

/**
 * Full name validation.
 */
export function validateName(name) {
  const cleaned = sanitizeInput(name);
  if (!cleaned) return 'Full name is required';
  if (cleaned.length < 2) return 'Name must be at least 2 characters';
  if (cleaned.length > 100) return 'Name is too long';
  // allow letters, spaces, hyphens, apostrophes, unicode
  if (/[<>"'`;{}()&|\\]/.test(cleaned)) return 'Name contains invalid characters';
  return '';
}

/**
 * Confirm-password validation.
 */
export function validateConfirmPassword(password, confirmPassword) {
  if (!confirmPassword) return 'Please confirm your password';
  if (password !== confirmPassword) return 'Passwords do not match';
  return '';
}
