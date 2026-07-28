/* eslint-disable no-unused-vars */
import { motion } from 'framer-motion';

/**
 * Password strength meter bar — shows 4 segments that light up
 * based on the score (0–4) from evaluatePasswordStrength().
 */
export default function PasswordStrength({ score, label }) {
  if (score === 0 && !label) return null;

  const getBarClass = (index) => {
    if (index >= score) return 'password-strength-bar';
    if (score <= 1) return 'password-strength-bar active';
    if (score <= 2) return 'password-strength-bar active medium';
    return 'password-strength-bar active strong';
  };

  return (
    <motion.div
      className="password-strength"
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.2 }}
    >
      <div className="password-strength-bars">
        {[0, 1, 2, 3].map((i) => (
          <motion.div
            key={i}
            className={getBarClass(i)}
            initial={{ scaleX: 0 }}
            animate={{ scaleX: 1 }}
            transition={{ duration: 0.3, delay: i * 0.06 }}
            style={{ transformOrigin: 'left' }}
          />
        ))}
      </div>
      {label && (
        <span className="password-strength-label">{label}</span>
      )}
    </motion.div>
  );
}
