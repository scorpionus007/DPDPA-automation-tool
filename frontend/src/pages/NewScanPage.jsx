/* eslint-disable no-unused-vars */
import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  History,
  FileText,
  Settings,
  Shield,
  User,
  LogOut,
  Link as LinkIcon,
  Search,
  FolderOpen,
  Lock,
  CheckCircle2,
  Github,
  Loader2,
  Eye,
  Download,
  X
} from 'lucide-react';
import { useNavigate, NavLink } from 'react-router-dom';
import { apiFetch, API_BASE_URL } from '../utils/api';
import '../styles/dashboard.css';
import '../styles/newScan.css';

export default function NewScanPage() {
  const navigate = useNavigate();
  const [repos, setRepos] = useState([]);
  const [userData, setUserData] = useState(null);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStages, setScanStages] = useState([]);
  const [lastScanId, setLastScanId] = useState(null);
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [viewPdfUrl, setViewPdfUrl] = useState(null);
  const [modalTitle, setModalTitle] = useState('');

  // Scan Options
  const [skipDeepReview, setSkipDeepReview] = useState(false);
  const [includeTests, setIncludeTests] = useState(false);

  useEffect(() => {
    async function init() {
      try {
        const me = await apiFetch('/auth/me');
        setUserData(me);
        if (me?.github_id) {
          fetchRepos();
        }
      } catch (err) {
        console.error('Failed to fetch user:', err);
      } finally {
        setLoading(false);
      }
    }
    init();
  }, []);

  // Sync Browser Tab Title with Modal
  useEffect(() => {
    if (viewModalOpen && modalTitle) {
      document.title = modalTitle;
    } else {
      document.title = "DPDP Scanner — Compliance Intelligence";
    }
  }, [viewModalOpen, modalTitle]);

  // Cleanup Blob URL when modal closes
  useEffect(() => {
    if (!viewModalOpen && viewPdfUrl) {
      window.URL.revokeObjectURL(viewPdfUrl);
      setViewPdfUrl(null);
    }
  }, [viewModalOpen, viewPdfUrl]);

  const fetchRepos = async () => {
    setLoadingRepos(true);
    try {
      const data = await apiFetch('/github/repos');
      // Transform GitHub API response to our repo format
      const transformed = data.map(repo => ({
        id: repo.id,
        name: repo.full_name,
        visibility: repo.private ? 'Private' : 'Public',
        updated: `Updated ${new Date(repo.updated_at).toLocaleDateString()}`,
        selected: false,
        url: repo.clone_url
      }));
      setRepos(transformed);
    } catch (err) {
      console.error('Failed to fetch repos:', err);
    } finally {
      setLoadingRepos(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!lastScanId) return;
    try {
      const response = await fetch(`${API_BASE_URL}/scans/${lastScanId}/report?download=true`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Download failed');
      const blob = await response.blob();

      const file = new File([blob], `report_scan_${lastScanId}.pdf`, { type: 'application/pdf' });
      const url = window.URL.createObjectURL(file);
      const link = document.createElement('a');
      link.href = url;
      link.download = `report_scan_${lastScanId}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => window.URL.revokeObjectURL(url), 100);
    } catch (err) {
      console.error('Download error:', err);
    }
  };

  const handleViewReport = async () => {
    if (!lastScanId) return;
    const fileName = `report_scan_${lastScanId}.pdf`;
    setModalTitle(fileName);

    // Close scanning modal first to show report 'directly'
    setScanning(false);
    setViewModalOpen(true);

    try {
      const response = await fetch(`${API_BASE_URL}/scans/${lastScanId}/report`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Failed to load report');
      const blob = await response.blob();
      const pdfFile = new File([blob], fileName, { type: 'application/pdf' });
      const url = window.URL.createObjectURL(pdfFile);
      setViewPdfUrl(url);
    } catch (err) {
      console.error('View error:', err);
    }
  };

  const resetSelection = () => {
    setRepos(repos.map(r => ({ ...r, selected: false })));
    setRepoUrl('');
    setLastScanId(null);
    setScanProgress(0);
    setScanStatus('');
    setScanStages([]);
  };

  const closePdfModal = () => {
    setViewModalOpen(false);
    resetSelection();
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  const handleConnectGithub = () => {
    const emailParam = userData?.email ? `&current_email=${encodeURIComponent(userData.email)}` : '';
    window.location.href = `http://localhost:8000/auth/github/login?redirect=/new-scan${emailParam}`;
  };

  const handleSelect = (id) => {
    setRepos(repos.map(repo => ({
      ...repo,
      selected: repo.id === id ? !repo.selected : false
    })));
  };

  const handleUrlChange = (e) => {
    const url = e.target.value;
    setRepoUrl(url);

    // Clear repo selection when typing a manual URL to avoid confusion
    if (url) {
      setRepos(repos.map(r => ({ ...r, selected: false })));
    }
  };

  const handleContinueScan = async () => {
    const finalUrl = selectedRepo ? (selectedRepo.url || repoUrl) : repoUrl;
    if (!finalUrl || finalUrl.trim() === '') {
      alert("Please provide a repository URL or local path.");
      return;
    }

    setScanning(true);
    setScanStatus('Connecting...');
    setScanProgress(5);
    setScanStages([{ text: 'Connecting to repository', time: new Date().toLocaleTimeString() }]);

    try {
      const response = await fetch(`${API_BASE_URL}/scans/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ 
          repo_url: finalUrl,
          skip_deep_review: skipDeepReview,
          include_tests: includeTests
        })
      });

      if (!response.ok) throw new Error('Failed to start scan');

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');

        // Keep the last partial line in the buffer
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmedLine = line.trim();
          if (trimmedLine.startsWith('data: ')) {
            try {
              const jsonContent = trimmedLine.substring(6).trim();
              if (!jsonContent) continue;

              const data = JSON.parse(jsonContent);
              if (data.error) throw new Error(data.error);
              
              if (data.stage) {
                setScanStatus(data.stage);
                setScanStages(prev => {
                  if (prev.some(s => s.text === data.stage)) return prev;
                  return [...prev, { text: data.stage, time: new Date().toLocaleTimeString() }];
                });
              }
              
              if (data.progress !== undefined) setScanProgress(data.progress);

              if (data.progress === 100) {
                if (data.scan_id) setLastScanId(data.scan_id);
                setScanStatus('Success! Analysis complete.');
                // We keep selection active while modal is open, 
                // but resetSelection() is called when closing the final result (PDF)
              }
            } catch (e) {
              console.warn('Error parsing SSE line:', line, e);
            }
          }
        }
      }
    } catch (err) {
      console.error(err);
      setScanStatus('Failed: ' + err.message);
      setScanStages(prev => [...prev, { text: 'Scan Failed', error: true, time: new Date().toLocaleTimeString() }]);
    }
  };

  const filteredRepos = repos.filter(r =>
    r.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // If a manual URL or path is provided, add it to the top of the list
  if (repoUrl && repoUrl.trim().length > 2) {
    const isRemote = repoUrl.startsWith('http') || repoUrl.includes('@');
    const manualRepo = {
      id: 'manual',
      name: repoUrl.split(/[\\/]/).filter(Boolean).pop()?.replace('.git', '') || 'Manual Path',
      visibility: isRemote ? 'Remote' : 'Local',
      updated: 'Manual Entry',
      selected: !repos.some(r => r.selected),
      url: repoUrl
    };
    // Only add if not already in the list
    if (!repos.some(r => r.url === repoUrl)) {
      filteredRepos.unshift(manualRepo);
    }
  }

  // Sort: Selected repo always at the top
  const sortedRepos = [...filteredRepos].sort((a, b) => {
    if (a.selected && !b.selected) return -1;
    if (!a.selected && b.selected) return 1;
    return 0;
  });

  const selectedRepo = repos.find(r => r.selected) || (repoUrl ? { url: repoUrl } : null);

  if (loading) {
    return (
      <div className="dashboard-layout" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-dark)' }}>
        <Loader2 className="spinner" style={{ width: '3rem', height: '3rem' }} />
      </div>
    );
  }

  return (
    <div className="dashboard-layout">
      {/* ─── Scanning Modal ─── */}
      {scanning && (
        <div className="scan-modal-overlay">
          <div className="scan-modal" style={{ maxWidth: '500px' }}>
            {scanProgress < 100 && !scanStatus.startsWith('Failed') ? (
              <div className="scan-modal-icon">
                <Loader2 className="spinner" size={32} />
              </div>
            ) : scanStatus.startsWith('Failed') ? (
              <div className="scan-modal-icon" style={{ background: '#fef2f2', color: '#ef4444' }}>
                <X size={32} />
              </div>
            ) : (
              <div className="scan-completed-icon">
                <CheckCircle2 size={64} />
              </div>
            )}

            <h3>{scanProgress < 100 && !scanStatus.startsWith('Failed') ? 'Scanning Repository' : scanStatus.startsWith('Failed') ? 'Scan Failed' : 'Scan Success!'}</h3>
            <p style={{ marginBottom: '1.5rem' }}>
              {scanProgress < 100 && !scanStatus.startsWith('Failed')
                ? "We're analyzing your codebase for DPDP compliance. Our multi-layer LLM pipeline is currently identifying risks and gaps."
                : scanStatus.startsWith('Failed')
                ? scanStatus.replace('Failed: ', '')
                : "Analysis finished successfully. Your detailed compliance report with remediation roadmap is ready."}
            </p>

            <div className="scan-progress-container">
              <div className="scan-progress-bar">
                <div
                  className={`scan-progress-fill ${scanProgress === 100 ? 'bg-success' : scanStatus.startsWith('Failed') ? 'bg-error' : ''}`}
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
              <div className={`scan-status-text ${scanProgress === 100 ? 'text-success' : scanStatus.startsWith('Failed') ? 'text-error' : ''}`}>
                {scanStatus}
              </div>
            </div>

            {/* Stages List */}
            <div className="scan-stages-list" style={{ width: '100%', textAlign: 'left', background: '#f8fafc', borderRadius: '12px', padding: '1rem', marginBottom: '2rem', maxHeight: '180px', overflowY: 'auto' }}>
              {scanStages.map((stage, i) => (
                <div key={i} className="scan-stage-item" style={{ fontSize: '0.75rem', color: stage.error ? '#ef4444' : '#475569', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', marginBottom: '8px', borderLeft: i === scanStages.length -1 && scanProgress < 100 ? '2px solid #3b82f6' : '2px solid #e2e8f0', paddingLeft: '8px' }}>
                  <span style={{ fontWeight: i === scanStages.length - 1 ? 600 : 400, flex: 1, lineHeight: '1.4' }}>{stage.text}</span>
                  <span style={{ color: '#94a3b8', whiteSpace: 'nowrap', fontSize: '0.7rem', marginTop: '1px' }}>{stage.time}</span>
                </div>
              ))}
            </div>

            {scanStatus.startsWith('Failed') ? (
              <button
                className="btn-modal-secondary"
                onClick={() => setScanning(false)}
                style={{ width: '100%' }}
              >
                TRY AGAIN
              </button>
            ) : scanProgress === 100 && (
              <div className="scan-modal-actions" style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
                <button
                  className="btn-modal-primary"
                  onClick={handleViewReport}
                  style={{ width: '100%', marginBottom: '4px' }}
                >
                  <Eye size={18} />
                  VIEW COMPLIANCE REPORT
                </button>
                <div style={{ display: 'flex', gap: '8px', width: '100%' }}>
                  <button
                    className="btn-modal-secondary"
                    onClick={handleDownloadReport}
                    style={{ flex: 1 }}
                  >
                    <Download size={18} />
                    DOWNLOAD PDF
                  </button>
                  <button
                    className="btn-modal-secondary"
                    onClick={() => { setScanning(false); resetSelection(); }}
                    style={{ flex: 1 }}
                  >
                    <Search size={18} />
                    NEW SCAN
                  </button>
                </div>
                <button
                    className="btn-modal-secondary"
                    onClick={() => { resetSelection(); navigate('/dashboard'); }}
                    style={{ width: '100%', marginTop: '4px' }}
                  >
                    <LayoutDashboard size={18} />
                    RETURN TO DASHBOARD
                  </button>
              </div>
            )}
          </div>
        </div>
      )}

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
          <NavLink to="/dashboard" className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
            <LayoutDashboard />
            <span>Dashboard</span>
          </NavLink>
          <NavLink to="/scan-history" className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
            <History />
            <span>Scan History</span>
          </NavLink>
          <NavLink to="/reports" className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
            <FileText />
            <span>Reports</span>
          </NavLink>
        </nav>

        <span className="sidebar-section-label">System</span>
        <nav className="sidebar-nav">
          <NavLink to="/settings" className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
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
      <main className="dashboard-main ns-main-container" style={{ padding: '2rem' }}>
        <div className="ns-breadcrumb">
          <NavLink to="/dashboard" className="ns-breadcrumb-link">DASHBOARD</NavLink>
          <span className="ns-breadcrumb-separator">&gt;</span>
          <NavLink to="/new-scan" className="ns-breadcrumb-link">NEW SCAN</NavLink>
          <span className="ns-breadcrumb-separator">&gt;</span>
          <span className="ns-breadcrumb-active">CONNECT REPOSITORY</span>
        </div>

        <div className="ns-card">
          <div className="ns-header">
            <h2>Analyze Repository</h2>
            <p>Perform a deep-layer compliance audit against India's DPDP Act 2023 guidelines.</p>
          </div>

          <div className="ns-section">
            <label className="ns-label">REPOSITORY URL / PATH</label>
            <div className="ns-input-group">
              <LinkIcon className="ns-input-icon" />
              <input
                type="text"
                placeholder="e.g., https://github.com/username/repo"
                className="ns-input"
                value={repoUrl}
                onChange={handleUrlChange}
              />
            </div>
          </div>

          <div className="ns-divider">
            <span>OR SELECT CONNECTED REPO</span>
          </div>

          {!userData?.github_id ? (
            <div className="ns-github-connect" style={{ flexDirection: 'column', alignItems: 'center' }}>
              <button className="ns-btn-github" onClick={handleConnectGithub}>
                <Github className="ns-btn-icon" />
                CONNECT GITHUB ACCOUNT
              </button>
            </div>
          ) : (
            <div className="ns-repos-section" style={{ marginBottom: '2rem' }}>
              <div className="ns-repos-header">
                <label className="ns-label mb-0">YOUR REPOSITORIES</label>
                <div className="ns-search-group">
                  <Search className="ns-search-icon" />
                  <input
                    type="text"
                    placeholder="Search repositories..."
                    className="ns-search-input"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
              </div>

              <div className="ns-repos-list" style={{ maxHeight: '300px', overflowY: 'auto', border: '1px solid #f1f5f9', borderRadius: '12px', padding: '8px' }}>
                {loadingRepos ? (
                  <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
                    <Loader2 className="spinner" />
                  </div>
                ) : sortedRepos.length > 0 ? (
                  sortedRepos.map(repo => (
                    <div key={repo.id} className={`ns-repo-item ${repo.selected ? 'selected-bg' : ''}`} style={{ marginBottom: '8px' }}>
                      <div className="ns-repo-info">
                        {repo.selected ? (
                          <CheckCircle2 className="ns-repo-icon text-blue" />
                        ) : repo.visibility === 'Private' ? (
                          <Lock className="ns-repo-icon text-muted" />
                        ) : (
                          <FolderOpen className="ns-repo-icon text-muted" />
                        )}
                        <div className="ns-repo-details">
                          <span className="ns-repo-name">{repo.name}</span>
                          <span className="ns-repo-meta">{repo.visibility} &bull; {repo.updated}</span>
                        </div>
                      </div>
                      <button
                        className={`ns-btn-select ${repo.selected ? 'selected' : ''}`}
                        onClick={() => handleSelect(repo.id)}
                      >
                        {repo.selected ? 'SELECTED' : 'SELECT'}
                      </button>
                    </div>
                  ))
                ) : (
                  <div className="text-muted" style={{ textAlign: 'center', padding: '2rem' }}>
                    {searchTerm ? 'No repositories match your search.' : 'No repositories found.'}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Scan Options */}
          <div className="ns-options-section" style={{ background: '#f8fafc', padding: '1.5rem', borderRadius: '16px', marginBottom: '2.5rem', border: '1px solid #e2e8f0' }}>
            <label className="ns-label" style={{ marginBottom: '1rem', display: 'block' }}>SCAN CONFIGURATION</label>
            <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer', fontSize: '0.875rem', color: '#334155' }}>
                <input 
                  type="checkbox" 
                  checked={!skipDeepReview} 
                  onChange={(e) => setSkipDeepReview(!e.target.checked)} 
                  style={{ width: '18px', height: '18px' }}
                />
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <span style={{ fontWeight: 600 }}>Deep-Layer Audit</span>
                  <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Analyze logic & transitive data flows</span>
                </div>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer', fontSize: '0.875rem', color: '#334155' }}>
                <input 
                  type="checkbox" 
                  checked={includeTests} 
                  onChange={(e) => setIncludeTests(e.target.checked)} 
                  style={{ width: '18px', height: '18px' }}
                />
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <span style={{ fontWeight: 600 }}>Include Test Files</span>
                  <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Scan tests for PII leakage</span>
                </div>
              </label>
            </div>
          </div>

          <div className="ns-footer">
            <button className="ns-btn-cancel" onClick={() => navigate('/dashboard')}>BACK</button>
            <button
              className="ns-btn-continue"
              disabled={!selectedRepo && !repoUrl}
              onClick={handleContinueScan}
            >
              LAUNCH COMPLIANCE AUDIT
            </button>
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
              {viewPdfUrl ? (
                <iframe
                  src={`${viewPdfUrl}#toolbar=0&navpanes=0`}
                  className="pdf-frame"
                  title="Compliance Report PDF"
                />
              ) : (
                <div className="pdf-loading">
                  <Loader2 className="spinner" size={48} />
                  <p>Generating high-fidelity analysis...</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
