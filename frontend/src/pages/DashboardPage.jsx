import { useState, useEffect } from 'react';
import { useNavigate, NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  History,
  FileText,
  Settings,
  Download,
  ScanSearch,
  AlertTriangle,
  CheckCircle2,
  Eye,
  User,
  Shield,
  LogOut,
  Trash2,
  Database,
  Network,
  ArrowRight,
  Route,
  Server,
  X
} from 'lucide-react';
import { apiFetch, API_BASE_URL } from '../utils/api';
import '../styles/dashboard.css';

function getScoreClass(score) {
  if (score >= 80) return 'good';
  if (score >= 55) return 'moderate';
  return 'critical';
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [selectedPdfUrl, setSelectedPdfUrl] = useState(null);
  const [modalTitle, setModalTitle] = useState('');

  useEffect(() => {
    async function fetchData() {
      try {
        const [userData, statsData] = await Promise.all([
          apiFetch('/auth/me'),
          apiFetch(`/dashboard/stats?t=${Date.now()}`)
        ]);
        setUser(userData);
        setStats(statsData);
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  // Sync Browser Tab Title with Modal
  useEffect(() => {
    if (viewModalOpen && modalTitle) {
      document.title = modalTitle;
    } else {
      document.title = "DPDP Scanner — Compliance Intelligence";
    }
  }, [viewModalOpen, modalTitle]);

  const handleDownload = async (scan) => {
    if (!scan.report_path) return;
    try {
      const response = await fetch(`${API_BASE_URL}/scans/${scan.id}/report?download=true`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Download failed');
      
      const blob = await response.blob();
      const fileName = `report_${scan.repo_name}.pdf`;
      const file = new File([blob], fileName, { type: 'application/pdf' });
      const url = window.URL.createObjectURL(file);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => window.URL.revokeObjectURL(url), 100);
    } catch (err) {
      console.error('Download error:', err);
      alert('Failed to download report');
    }
  };

  const handleView = async (scan) => {
    if (!scan.report_path) return;
    const fileName = `report_${scan.repo_name}.pdf`;
    setModalTitle(fileName);
    
    try {
      const response = await fetch(`${API_BASE_URL}/scans/${scan.id}/report`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Failed to load PDF');
      
      const blob = await response.blob();
      const pdfFile = new File([blob], fileName, { type: 'application/pdf' });
      const url = window.URL.createObjectURL(pdfFile);
      setSelectedPdfUrl(url);
      setViewModalOpen(true);
    } catch (err) {
      console.error('View error:', err);
      alert('Failed to load PDF report');
    }
  };

  const closePdfModal = () => {
    if (selectedPdfUrl) {
      window.URL.revokeObjectURL(selectedPdfUrl);
    }
    setViewModalOpen(false);
    setSelectedPdfUrl(null);
  };

  const handleDelete = async (scanId) => {
    if (!window.confirm('Are you sure you want to permanently delete this scan?')) return;
    try {
      await apiFetch(`/scans/${scanId}`, { method: 'DELETE' });
      // Refresh dashboard data
      const statsData = await apiFetch('/dashboard/stats');
      setStats(statsData);
    } catch (err) {
      console.error('Failed to delete scan:', err);
      alert('Failed to delete scan');
    }
  };

  if (loading) {
    return (
      <div className="dashboard-layout" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-dark)' }}>
        <div className="spinner" style={{ width: '3rem', height: '3rem' }}></div>
      </div>
    );
  }

  const STAT_DATA = stats || {
    score: 0,
    grade: '-',
    gradeLabel: 'No data',
    totalFindings: 0,
    findingsHigh: 0,
    findingsMed: 0,
    findingsLow: 0,
    reposScanned: 0,
    reposNewThisWeek: 0,
    remediationMin: 0,
    remediationMax: 0,
  };

  const RECENT_SCANS = stats?.recentScans || [];

  const COMPLIANCE_SECTIONS = stats?.complianceMatrix || [
    { name: 'Consent Management', pct: 0, status: 'critical' },
    { name: 'Data Security', pct: 0, status: 'critical' },
    { name: 'Retention Policy', pct: 0, status: 'critical' },
    { name: 'Notice Accessibility', pct: 0, status: 'critical' },
    { name: 'Data Principal Rights', pct: 0, status: 'critical' },
  ];

  const topFlowFinding = RECENT_SCANS[0]?.findings?.find(f => f.rule?.startsWith('PII_FLOW_')) || null;

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
            <span className="sidebar-user-name">{user?.username || 'Guest'}</span>
          </div>
        </div>
      </aside>

      {/* ─── Main Content ─── */}
      <main className="dashboard-main">
        {/* Header */}
        <div className="dashboard-header">
          <div className="dashboard-header-left">
            <h1>Compliance Overview</h1>
            <p>Real-time DPDP compliance status for your organization.</p>
          </div>
          <div className="dashboard-header-actions">
            <button className="btn-primary" onClick={() => navigate('/new-scan')}>
              <ScanSearch />
              <span>New Scan</span>
            </button>
          </div>
        </div>

        {/* Stat Cards */}
        <div className="stat-cards">
          <div className="stat-card">
            <div className="stat-card-label">
              <span className="flex items-center gap-2"><Shield size={14} className="text-secondary" /> Compliance Score</span>
              <span className={`stat-card-badge status-${getScoreClass(STAT_DATA.score)}`}>Grade {STAT_DATA.grade}</span>
            </div>
            <div className="stat-card-value" style={{ color: '#0f172a', fontWeight: '800' }}>
              {STAT_DATA.score} <span className="text-xs text-muted">/100</span>
            </div>
            <div className="score-progress">
              <div
                className={`score-progress-fill bg-${getScoreClass(STAT_DATA.score)}`}
                style={{ width: `${STAT_DATA.score}%` }}
              />
            </div>
            <div className={`score-label text-${getScoreClass(STAT_DATA.score)}`}>
              <CheckCircle2 size={14} />
              <span>{STAT_DATA.gradeLabel}</span>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">
              <span className="flex items-center gap-2"><AlertTriangle size={14} className="text-error" /> Risk Exposure</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem' }}>
              <div className="stat-card-value">{STAT_DATA.totalFindings}</div>
              <div className="findings-pills" style={{ marginTop: 0, alignItems: 'flex-end' }}>
                <div className="finding-pill-group">
                  <span className="finding-pill high" style={{ color: '#ef4444' }}>{STAT_DATA.findingsHigh} Critical</span>
                  <span className="finding-pill-dot bg-error"></span>
                </div>
                <div className="finding-pill-group">
                  <span className="finding-pill medium" style={{ color: '#f59e0b' }}>{STAT_DATA.findingsMed} Warning</span>
                  <span className="finding-pill-dot bg-warn"></span>
                </div>
                <div className="finding-pill-group">
                  <span className="finding-pill low" style={{ color: '#10b981' }}>{STAT_DATA.findingsLow} Resolved</span>
                  <span className="finding-pill-dot bg-success"></span>
                </div>
              </div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-card-label">
              <span className="flex items-center gap-2"><Database size={14} className="text-primary" /> Audit Coverage</span>
            </div>
            <div className="stat-card-value">{STAT_DATA.reposScanned} <span className="text-xs text-muted">REPOS</span></div>
            <div className="stat-card-subtitle mt-2 flex items-center gap-1">
              <span className="text-success font-bold">+{STAT_DATA.reposNewThisWeek}</span>
              <span className="text-muted">new assets synced this week</span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-card-label">
              <span className="flex items-center gap-2"><Settings size={14} className="text-indigo" /> Remediation Debt</span>
            </div>
            <div className="stat-card-value">
              {Math.round((STAT_DATA.remediationEffort?.minHours || 0) / 8)} – {Math.round((STAT_DATA.remediationEffort?.maxHours || 0) / 8)} <span className="text-xs text-muted">DAYS</span>
            </div>
            <div className="stat-card-subtitle mt-2">
              <span className="font-mono text-indigo-400">{(STAT_DATA.remediationEffort?.maxHours || 0).toLocaleString()}</span>
              <span className="text-muted ml-1">TOTAL EST. OPS HOURS</span>
            </div>
          </div>
        </div>

        {/* Bottom Row */}
        <div className="dashboard-row">
          <div className="dash-card">
            <div className="dash-card-header">
              <span className="dash-card-title">Recent Compliance Audits</span>
              <NavLink to="/scan-history" className="dash-card-link">View All History</NavLink>
            </div>
            <table className="scans-table">
              <thead>
                <tr>
                  <th>Repository</th>
                  <th>Compliance Score</th>
                  <th>Findings</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {RECENT_SCANS.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <div className="scan-repo-name">{scan.repo_name}</div>
                      <div className="scan-repo-date">{new Date(scan.created_at).toLocaleDateString()}</div>
                    </td>
                    <td>
                      <span className={`scan-score ${getScoreClass(scan.score)}`}>
                         {scan.score}/100
                      </span>
                    </td>
                    <td>
                      <div className="findings-summary-mini">
                         <span className="f-dot high" title="High"></span> {scan.findings_high}
                         <span className="f-dot med" title="Medium"></span> {scan.findings_medium}
                         <span className="f-dot low" title="Low"></span> {scan.findings_low}
                      </div>
                    </td>
                    <td>
                      <span className={`status-badge ${getScoreClass(scan.score)}`}>
                        {scan.score >= 85 ? 'STRONG' : scan.score >= 70 ? 'ADEQUATE' : scan.score >= 55 ? 'NEEDS WORK' : 'CRITICAL'}
                      </span>
                    </td>
                    <td>
                      <div className="scan-actions">
                        <button 
                          className="scan-action-btn view" 
                          title="View report"
                          onClick={() => handleView(scan)}
                          disabled={!scan.report_path}
                        >
                          <Eye size={16} />
                        </button>
                        <button 
                          className="scan-action-btn download" 
                          title="Download PDF"
                          onClick={() => handleDownload(scan)}
                          disabled={!scan.report_path}
                        >
                          <Download size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {RECENT_SCANS.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: '2rem' }}>No scans performed yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="dash-card">
            <div className="dash-card-header">
              <span className="dash-card-title">Compliance Matrix</span>
            </div>
            <div className="compliance-list" style={{ marginBottom: '1.5rem' }}>
              {COMPLIANCE_SECTIONS.map((section) => (
                <div className="compliance-item" key={section.name}>
                  <div className="compliance-item-header">
                    <span className="compliance-item-name">{section.name}</span>
                    <span className="compliance-item-pct">{section.pct}%</span>
                  </div>
                  <div className="compliance-bar">
                    <div
                      className={`compliance-bar-fill ${section.status}`}
                      style={{ width: `${section.pct}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            <div className="dash-card-header" style={{ borderTop: '1px solid #f1f5f9', paddingTop: '1.25rem' }}>
               <span className="dash-card-title">Strategic Insight</span>
            </div>
            <div className="pro-tip" style={{ marginTop: '0.5rem' }}>
              <span className="pro-tip-icon">🛡️</span>
              <div className="pro-tip-content">
                <span className="pro-tip-label">DPDP ADVISORY</span>
                <span className="pro-tip-text">
                  {RECENT_SCANS[0]?.compliance_data?.llm_pipeline?.risk_narrative || 
                   "Improving retention triggers can boost your overall score by up to 12% in the next audit cycle."}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Privacy Inventory & Data Flows Section */}
        <div className="dash-card" style={{ marginTop: '1.25rem' }}>
          <div className="dash-card-header">
            <span className="dash-card-title">Privacy Inventory & Data Flows</span>
          </div>
          
          <div className="inventory-grid">
            {/* Live Flow Analysis (Full Width if exists) */}
            {topFlowFinding && (
              <div className="inventory-card" style={{ gridColumn: '1 / -1', background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.05), rgba(147, 51, 234, 0.05))', borderColor: 'rgba(59, 130, 246, 0.2)' }}>
                <div className="inventory-card-title" style={{ color: '#60a5fa' }}>
                  <Activity size={18} />
                  <span>Interactive Flow Analysis: {topFlowFinding.description.split('.')[0]}</span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', marginTop: '1rem', position: 'relative' }}>
                  {topFlowFinding.evidence?.flow_path?.map((step, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <div className="flow-step" style={{ marginBottom: 0, paddingLeft: '1.25rem' }}>
                        <div className="flow-step-dot" style={{ background: idx === 0 ? '#10b981' : idx === topFlowFinding.evidence.flow_path.length - 1 ? '#ef4444' : '#3b82f6' }}></div>
                        <div className="inventory-item-text">
                          <strong style={{ fontSize: '0.85rem' }}>{step.split('/').pop()}</strong>
                          <div className="text-muted" style={{ fontSize: '0.7rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '120px' }}>{step}</div>
                        </div>
                      </div>
                      {idx < topFlowFinding.evidence.flow_path.length - 1 && (
                        <ArrowRight size={14} className="text-muted" style={{ opacity: 0.5 }} />
                      )}
                    </div>
                  ))}
                </div>
                <div className="mt-1" style={{ display: 'flex', gap: '1.5rem', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '1rem', marginTop: '1rem' }}>
                   <div style={{ fontSize: '0.75rem' }}>
                      <span className="text-muted">Detected PII: </span>
                      <span style={{ color: '#e2e8f0' }}>{topFlowFinding.evidence?.pii_fields?.join(', ') || 'Sensitive Data'}</span>
                   </div>
                   <div style={{ fontSize: '0.75rem' }}>
                      <span className="text-muted">Verification: </span>
                      <span style={{ color: '#10b981' }}>{topFlowFinding.evidence?.flow_evidence?.ml_classifier || 'Statical Analysis'} ({(topFlowFinding.confidence * 100).toFixed(0)}%)</span>
                   </div>
                   <div style={{ fontSize: '0.75rem' }}>
                      <span className="text-muted">Taint Reached Sink: </span>
                      <span style={{ color: topFlowFinding.evidence?.flow_evidence?.taint_reached_sink ? '#ef4444' : '#10b981' }}>
                        {topFlowFinding.evidence?.flow_evidence?.taint_reached_sink ? 'YES' : 'LIKELY'}
                      </span>
                   </div>
                </div>
              </div>
            )}

            {/* Data Flows Card */}
            <div className="inventory-card">
              <div className="inventory-card-title">
                <Route size={18} />
                <span>Critical Data Flows</span>
              </div>
              <div className="inventory-list">
                {RECENT_SCANS[0]?.compliance_data?.repo_context?.data_flows?.length > 0 ? (
                  RECENT_SCANS[0].compliance_data.repo_context.data_flows.map((flow, i) => (
                    <div key={i} className="inventory-item">
                      <div className="inventory-item-icon"><ArrowRight size={14} /></div>
                      <span className="inventory-item-text">{flow}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-muted small" style={{ margin: '1rem 0', opacity: 0.6 }}>No data flows detected in latest scan.</p>
                )}
              </div>
            </div>

            {/* PII Storage Card */}
            <div className="inventory-card">
              <div className="inventory-card-title">
                <Database size={18} />
                <span>PII Storage Locations</span>
              </div>
              <div className="inventory-list">
                {RECENT_SCANS[0]?.compliance_data?.repo_context?.pii_storage_locations?.length > 0 ? (
                  RECENT_SCANS[0].compliance_data.repo_context.pii_storage_locations.map((loc, i) => (
                    <div key={i} className="inventory-item">
                      <div className="inventory-item-icon"><Server size={14} /></div>
                      <span className="inventory-item-text">{loc}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-muted small" style={{ margin: '1rem 0', opacity: 0.6 }}>No PII storage locations detected.</p>
                )}
              </div>
            </div>

            {/* Privacy Risk Surface Card */}
            <div className="inventory-card">
              <div className="inventory-card-title">
                <Shield size={18} />
                <span>Risk Surface Analysis</span>
              </div>
              <div className="inventory-list">
                <div className="inventory-item">
                  <div className="inventory-item-text">
                    <strong style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.8rem', color: '#94a3b8' }}>TECH STACK</strong>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                      {RECENT_SCANS[0]?.compliance_data?.repo_context?.tech_stack?.length > 0 ? (
                        RECENT_SCANS[0].compliance_data.repo_context.tech_stack.map(tech => (
                          <span key={tech} className="inventory-tag">{tech}</span>
                        ))
                      ) : (
                        <span className="inventory-tag">Not detected</span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="inventory-item" style={{ border: 'none' }}>
                  <div className="inventory-item-text">
                    <strong style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.8rem', color: '#94a3b8' }}>RISK SUMMARY</strong>
                    <div style={{ lineHighlight: '1.4', fontStyle: 'italic' }}>
                      {RECENT_SCANS[0]?.compliance_data?.repo_context?.risk_surface_summary || "Perform a deep-layer audit for full risk surface analysis."}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* PDF Viewer Modal */}
      {viewModalOpen && (
        <div className="pdf-modal" onClick={closePdfModal}>
          <div className="pdf-modal-container" onClick={(e) => e.stopPropagation()}>
            <div className="pdf-modal-header">
              <div className="pdf-modal-title">
                <FileText size={18} />
                <span>{modalTitle}</span>
              </div>
              <button className="pdf-modal-close" onClick={closePdfModal}>
                <X size={20} />
              </button>
            </div>
            <div className="pdf-modal-body" style={{ background: '#525659' }}>
               <iframe 
                src={`${selectedPdfUrl}#toolbar=0`} 
                className="pdf-frame" 
                title={modalTitle}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
