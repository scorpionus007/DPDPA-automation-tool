import { Routes, Route, Navigate } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import DashboardPage from './pages/DashboardPage';
import NewScanPage from './pages/NewScanPage';
import ScanHistoryPage from './pages/ScanHistoryPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import AuthCallback from './pages/AuthCallback';
import OrgConnectPage from './pages/org/OrgConnectPage';
import OrgRepoListPage from './pages/org/OrgRepoListPage';
import OrgScanQueuePage from './pages/org/OrgScanQueuePage';
import OrgDashboardPage from './pages/org/OrgDashboardPage';
import OrgEntityGraphPage from './pages/org/OrgEntityGraphPage';
import OrgReportsPage from './pages/org/OrgReportsPage';

function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/auth/callback" element={<AuthCallback />} />
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/new-scan" element={<NewScanPage />} />
      <Route path="/scan-history" element={<ScanHistoryPage />} />
      <Route path="/reports" element={<ReportsPage />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="/org/connect" element={<OrgConnectPage />} />
      <Route path="/org/repos" element={<OrgRepoListPage />} />
      <Route path="/org/scans" element={<OrgScanQueuePage />} />
      <Route path="/org" element={<OrgDashboardPage />} />
      <Route path="/org/data-flows" element={<OrgEntityGraphPage />} />
      <Route path="/org/reports" element={<OrgReportsPage />} />
    </Routes>
  );
}

export default App;
