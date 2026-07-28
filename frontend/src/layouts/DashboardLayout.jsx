import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  History,
  FileText,
  Settings,
  ScanSearch,
  Building2,
  GitBranch,
  Network,
  Layers,
  LogOut,
} from 'lucide-react';
import { useOrg } from '../contexts/OrgContext';

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/new-scan', icon: ScanSearch, label: 'New Scan' },
  { to: '/scan-history', icon: History, label: 'Scan History' },
  { to: '/reports', icon: FileText, label: 'Reports' },
  { to: '/org', icon: Building2, label: 'Org Dashboard' },
  { to: '/org/repos', icon: GitBranch, label: 'Org Repos' },
  { to: '/org/scans', icon: Layers, label: 'Bulk Scans' },
  { to: '/org/data-flows', icon: Network, label: 'Data Flows' },
  { to: '/org/reports', icon: FileText, label: 'Org Reports' },
  { to: '/org/connect', icon: Building2, label: 'Connect Org' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export default function DashboardLayout({ children, title }) {
  const navigate = useNavigate();
  const { orgs, activeOrg, activeOrgId, setActiveOrgId } = useOrg();

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  return (
    <div className="dashboard-container" style={{ display: 'flex', minHeight: '100vh' }}>
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>DPDP Scanner</h2>
        </div>
        {orgs.length > 0 && (
          <div className="org-switcher" style={{ padding: '0 1rem 1rem' }}>
            <label style={{ fontSize: '0.75rem', opacity: 0.7 }}>Organization</label>
            <select
              value={activeOrgId || ''}
              onChange={(e) => setActiveOrgId(parseInt(e.target.value, 10))}
              style={{ width: '100%', marginTop: 4, padding: 6, borderRadius: 4 }}
            >
              {orgs.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.display_name} ({o.role})
                </option>
              ))}
            </select>
          </div>
        )}
        <nav className="sidebar-nav">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to} className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}>
              <Icon size={18} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <button type="button" className="logout-btn" onClick={handleLogout}>
          <LogOut size={18} /> Log out
        </button>
      </aside>
      <main className="main-content">
        {title && <h1 className="page-title">{title}</h1>}
        {activeOrg && (
          <p style={{ opacity: 0.7, marginTop: -8, marginBottom: 16 }}>
            Active org: <strong>{activeOrg.display_name}</strong>
          </p>
        )}
        {children}
      </main>
    </div>
  );
}
