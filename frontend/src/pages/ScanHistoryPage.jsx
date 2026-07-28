/* eslint-disable no-unused-vars */
import React, { useState, useEffect, useRef } from 'react';
import {
  LayoutDashboard,
  History,
  FileText,
  Settings,
  Shield,
  User,
  LogOut,
  Search,
  Filter,
  Eye,
  Download,
  Trash2,
  X
} from 'lucide-react';
import { NavLink, useNavigate } from 'react-router-dom';
import { apiFetch, API_BASE_URL } from '../utils/api';
import '../styles/dashboard.css';
import '../styles/scanHistory.css';

function getScoreColor(score) {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  return '#ef4444';
}

export default function ScanHistoryPage() {
  const navigate = useNavigate();
  const pdfContainerRef = useRef(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [scans, setScans] = useState([]);
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [viewPdfUrl, setViewPdfUrl] = useState(null);
  const [modalTitle, setModalTitle] = useState('');
  const [sortConfig, setSortConfig] = useState({ key: 'created_at', direction: 'desc' });

  useEffect(() => {
    async function fetchData() {
      try {
        const [me, scanList] = await Promise.all([
          apiFetch('/auth/me'),
          apiFetch(`/scans?t=${Date.now()}`)
        ]);
        setUserData(me);
        setScans(scanList);
      } catch (err) {
        console.error('Failed to fetch history:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
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

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

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
      
      // Method 1: File System Access API (Recommended for Windows)
      if ('showSaveFilePicker' in window) {
        try {
          const handle = await window.showSaveFilePicker({
            suggestedName: `report_${scan.repo_name}.pdf`,
            types: [{ description: 'PDF Documents', accept: {'application/pdf': ['.pdf']} }],
          });
          const writable = await handle.createWritable();
          await writable.write(blob);
          await writable.close();
          return;
        } catch (e) {
          if (e.name === 'AbortError') return;
        }
      }
      
      // Method 2: Force standard browser download
      // Using File instead of Blob can help some browsers with naming
      const file = new File([blob], `report_${scan.repo_name}.pdf`, { type: 'application/pdf' });
      const url = window.URL.createObjectURL(file);
      const link = document.createElement('a');
      link.href = url;
      link.download = `report_${scan.repo_name}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => window.URL.revokeObjectURL(url), 100);
    } catch (err) {
      console.error('Download error:', err);
    }
  };

  const handleView = async (scan) => {
    if (!scan.report_path) return;
    const fileName = `report_${scan.repo_name}.pdf`;
    setModalTitle(fileName);
    setViewModalOpen(true);
    
    try {
      const response = await fetch(`${API_BASE_URL}/scans/${scan.id}/report`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Failed to load data');
      
      const blob = await response.blob();
      // Use File instead of Blob to give the browser a filename hint
      const pdfFile = new File([blob], `report_${scan.repo_name}.pdf`, { type: 'application/pdf' });
      const url = window.URL.createObjectURL(pdfFile);
      setViewPdfUrl(url);
    } catch (err) {
      console.error('View error:', err);
    }
  };

  const closePdfModal = () => {
    setViewModalOpen(false);
  };

  const handleDelete = async (scanId) => {
    if (!window.confirm('Are you sure you want to permanently delete this scan?')) return;
    try {
      await apiFetch(`/scans/${scanId}`, { method: 'DELETE' });
      setScans(scans.filter(s => s.id !== scanId));
    } catch (err) {
      console.error('Failed to delete scan:', err);
      alert('Failed to delete scan');
    }
  };

  const filteredScans = scans
    .filter(s => 
      s.repo_name.toLowerCase().includes(searchTerm.toLowerCase()) || 
      s.id.toString().includes(searchTerm.toLowerCase())
    )
    .sort((a, b) => {
      if (sortConfig.key === 'score') {
        return sortConfig.direction === 'asc' ? a.score - b.score : b.score - a.score;
      }
      const dateA = new Date(a.created_at);
      const dateB = new Date(b.created_at);
      return sortConfig.direction === 'asc' ? dateA - dateB : dateB - dateA;
    });

  const toggleSort = () => {
    if (sortConfig.key === 'created_at') {
      setSortConfig({ key: 'score', direction: 'desc' });
    } else if (sortConfig.key === 'score' && sortConfig.direction === 'desc') {
      setSortConfig({ key: 'score', direction: 'asc' });
    } else {
      setSortConfig({ key: 'created_at', direction: 'desc' });
    }
  };

  if (loading) {
    return (
      <div className="dashboard-layout" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-dark)' }}>
        <div className="spinner" style={{ width: '3rem', height: '3rem' }}></div>
      </div>
    );
  }

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
      <main className="dashboard-main sh-main">
        <div className="dashboard-header mb-2">
          <div className="dashboard-header-left">
            <h1>Scan History</h1>
            <p>Review comprehensive logs of all repository compliance scans.</p>
          </div>
        </div>

        <div className="sh-card">
          <div className="sh-toolbar">
            <div className="ns-search-group sh-search">
              <Search className="ns-search-icon" />
              <input 
                type="text" 
                placeholder="Search repository, branch, or ID..." 
                className="ns-search-input"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            
            <div className="sh-actions">
              <button 
                className={`sh-btn-outline ${sortConfig.key === 'score' ? 'active-filter' : ''}`}
                onClick={toggleSort}
                title={`Sorting by ${sortConfig.key === 'score' ? 'Compliance Score' : 'Date'}`}
              >
                <Filter size={16} />
                <span>Sort: {sortConfig.key === 'score' ? (sortConfig.direction === 'desc' ? 'Highest Score' : 'Lowest Score') : 'Latest'}</span>
              </button>
            </div>
          </div>

          <div className="sh-table-container">
            <table className="sh-table">
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Repository Target</th>
                  <th>Date & Time</th>
                  <th>Compliance Score</th>
                  <th>Issues</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <span className="sh-scan-id">SCN-{scan.id}</span>
                    </td>
                    <td>
                      <div className="sh-repo-name">{scan.repo_name}</div>
                      <div className="sh-repo-branch">{scan.branch}</div>
                    </td>
                    <td>
                      <div className="sh-date">{new Date(scan.created_at).toLocaleString()}</div>
                    </td>
                    <td>
                      <div className="sh-score-wrap">
                        <span className="sh-score-val" style={{ color: getScoreColor(scan.score) }}>{scan.score}</span>
                        <div className="sh-score-bar">
                          <div className="sh-score-fill" style={{ width: `${scan.score}%`, backgroundColor: getScoreColor(scan.score) }} />
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className="sh-findings">{scan.findings_count} found</span>
                    </td>
                    <td>
                      <span className={`sh-status-badge ${scan.status.toLowerCase()}`}>{scan.status.toUpperCase()}</span>
                    </td>
                    <td>
                      <div className="sh-actions" style={{ display: 'flex', gap: '8px' }}>
                        <button 
                          className="sh-action-btn delete" 
                          title="Delete Scan" 
                          onClick={() => handleDelete(scan.id)}
                          style={{ border: 'none', background: 'none', cursor: 'pointer', color: '#ef4444' }}
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {filteredScans.length === 0 && (
                  <tr>
                    <td colSpan="7" style={{ textAlign: 'center', padding: '2rem' }}>No scans found.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          
          <div className="sh-pagination">
            <span className="sh-page-info">Showing {filteredScans.length} entries</span>
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
                  title={modalTitle}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                />
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'white' }}>
                  <div className="spinner"></div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
