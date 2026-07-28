import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  History,
  FileText,
  Settings,
  Shield,
  User,
  LogOut,
  Bell,
  Lock,
  Globe,
  Database,
  Github,
  Mail,
  Smartphone,
  Save
} from 'lucide-react';
import { NavLink, useNavigate } from 'react-router-dom';
import { apiFetch, API_BASE_URL } from '../utils/api';
import '../styles/dashboard.css';
import '../styles/settings.css';

const TABS = [
  { id: 'general', label: 'General Info', icon: <User size={18} /> },
  { id: 'notifications', label: 'Notifications', icon: <Bell size={18} /> },
  { id: 'integrations', label: 'Integrations', icon: <Globe size={18} /> },
  { id: 'security', label: 'Security & Access', icon: <Lock size={18} /> },
  { id: 'data', label: 'Data Management', icon: <Database size={18} /> },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('general');
  const navigate = useNavigate();
  const [userData, setUserData] = useState(null);

  useEffect(() => {
    async function fetchUser() {
      try {
        const me = await apiFetch('/auth/me');
        setUserData(me);
      } catch (err) {
        console.error('Failed to fetch user:', err);
      }
    }
    fetchUser();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  return (
    <div className="dashboard-layout">
      {/* ─── Sidebar ─── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-brand-icon">
            <Shield strokeWidth={2.2} />
          </div>
          <span className="sidebar-brand-name">Compliance Scan</span>
        </div>

        <span className="sidebar-section-label">Main Menu</span>
        <nav className="sidebar-nav">
          <NavLink to="/dashboard" className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`} style={{textDecoration: 'none'}}>
            <LayoutDashboard />
            <span>Dashboard</span>
          </NavLink>
          <NavLink to="/scan-history" className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`} style={{textDecoration: 'none'}}>
            <History />
            <span>Scan History</span>
          </NavLink>
          <NavLink to="/reports" className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`} style={{textDecoration: 'none'}}>
            <FileText />
            <span>Reports</span>
          </NavLink>
        </nav>

        <span className="sidebar-section-label">System</span>
        <nav className="sidebar-nav">
          <NavLink to="/settings" className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`} style={{textDecoration: 'none'}}>
            <Settings />
            <span>Settings</span>
          </NavLink>
          <button className="sidebar-nav-item logout-btn" onClick={handleLogout}>
            <LogOut />
            <span>Logout</span>
          </button>
        </nav>

        <div className="sidebar-user">
          <div className="sidebar-user-avatar">
            <User />
          </div>
          <div className="sidebar-user-info">
            <span className="sidebar-user-name">{userData?.username || 'Guest'}</span>
          </div>
        </div>
      </aside>

      {/* ─── Main Content ─── */}
      <main className="dashboard-main st-main">
        <div className="dashboard-header mb-0">
          <div className="dashboard-header-left">
            <h1>Organization Settings</h1>
            <p>Manage your account, organization preferences, and integrations.</p>
          </div>
        </div>

        <div className="st-container">
          <div className="st-sidebar">
            {TABS.map((tab) => (
              <button 
                key={tab.id} 
                className={`st-tab ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.icon}
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          <div className="st-content">
            {activeTab === 'general' && (
              <div className="st-pane fade-in">
                <h2>General Information</h2>
                <div className="st-divider"></div>
                
                <div className="st-form-row">
                  <div className="st-form-group">
                    <label>Username</label>
                    <input type="text" defaultValue={userData?.username || ''} className="st-input" />
                  </div>
                  <div className="st-form-group">
                    <label>Email Address</label>
                    <input type="text" defaultValue={userData?.email || ''} disabled className="st-input disabled" />
                  </div>
                </div>

                <div className="st-form-row">
                  <div className="st-form-group">
                    <label>Organization Name</label>
                    <input type="text" defaultValue="Acme Corp India" className="st-input" />
                  </div>
                </div>

                <div className="st-form-row">
                  <div className="st-form-group">
                    <label>Default Compliance Standard</label>
                    <select className="st-input st-select">
                      <option>DPDP Act (India)</option>
                      <option>GDPR (EU)</option>
                      <option>CCPA (California)</option>
                    </select>
                  </div>
                </div>

                <div className="st-actions">
                  <button className="btn-outline">Cancel</button>
                  <button className="btn-primary" style={{gap: '0.5rem', display: 'flex'}}>
                    <Save size={16} /> Save Changes
                  </button>
                </div>
              </div>
            )}

            {/* Notifications Tab */}
            {activeTab === 'notifications' && (
              <div className="st-pane fade-in">
                <h2>Notification Preferences</h2>
                <div className="st-divider"></div>

                <div className="st-toggle-list">
                  <div className="st-toggle-item">
                     <div className="st-toggle-info">
                        <Mail size={20} className="text-muted" />
                        <div>
                          <strong>Critical Findings Alert</strong>
                          <p>Receive email when a critical compliance vulnerability is scanned.</p>
                        </div>
                     </div>
                     <label className="st-switch">
                       <input type="checkbox" defaultChecked />
                       <span className="st-slider round"></span>
                     </label>
                  </div>

                  <div className="st-toggle-item">
                     <div className="st-toggle-info">
                        <Smartphone size={20} className="text-muted" />
                        <div>
                          <strong>Weekly Summary Report</strong>
                          <p>Get a digest of the week's scan grades across all repositories.</p>
                        </div>
                     </div>
                     <label className="st-switch">
                       <input type="checkbox" defaultChecked />
                       <span className="st-slider round"></span>
                     </label>
                  </div>
                </div>

                <div className="st-actions mt-auto">
                  <button className="btn-primary">Save Preferences</button>
                </div>
              </div>
            )}

            {/* Integrations Tab */}
            {activeTab === 'integrations' && (
              <div className="st-pane fade-in">
                <h2>Connected Services</h2>
                <div className="st-divider"></div>

                <div className="st-integration-card">
                  <div className="st-integration-header">
                    <div className="st-integration-title">
                      <div className="st-integration-icon-container bg-gray">
                        <Github size={24} />
                      </div>
                      <div>
                        <h3>GitHub Enterprise</h3>
                        <span className="st-badge active">{userData?.github_id ? 'Connected' : 'Not Connected'}</span>
                      </div>
                    </div>
                    {userData?.github_id && <button className="btn-outline text-red">Disconnect</button>}
                    {!userData?.github_id && (
                      <button 
                        className="btn-outline" 
                        onClick={() => {
                          const emailParam = userData?.email ? `&current_email=${encodeURIComponent(userData.email)}` : '';
                          window.location.href = `http://localhost:8000/auth/github/login?redirect=/settings${emailParam}`;
                        }}
                      >
                        Connect
                      </button>
                    )}
                  </div>
                  <p className="st-integration-desc">
                    Allows Compliance Scan to automatically read repositories for DPDP policies, retention code, and potential data-leaks.
                  </p>
                </div>
              </div>
            )}

            {(activeTab === 'security' || activeTab === 'data') && (
              <div className="st-pane fade-in" style={{ alignItems: 'center', justifyContent: 'center', minHeight: '400px', display: 'flex', flexDirection: 'column' }}>
                <Lock size={48} color="#cbd5e1" style={{ marginBottom: '1rem' }} />
                <h3 style={{ color: '#475569' }}>Restricted Access</h3>
                <p style={{ color: '#94a3b8', textAlign: 'center', maxWidth: '300px' }}>
                  You require Super Admin privileges to view and modify {activeTab === 'security' ? 'Security Options' : 'Data Management'}.
                </p>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
