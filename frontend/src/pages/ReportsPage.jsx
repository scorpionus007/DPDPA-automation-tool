/* eslint-disable no-unused-vars */
import React, { useState, useEffect, useRef } from 'react';
// ... existing lucide-react imports ...
import {
  LayoutDashboard,
  History,
  FileText,
  Settings,
  Shield,
  User,
  LogOut,
  Download,
  Eye,
  Calendar,
  Filter,
  FileSearch,
  Trash2,
  X
} from 'lucide-react';
import { NavLink, useNavigate } from 'react-router-dom';
import { apiFetch, API_BASE_URL } from '../utils/api';
import '../styles/dashboard.css';
import '../styles/reports.css';

export default function ReportsPage() {
  const navigate = useNavigate();
  const pdfContainerRef = useRef(null);
  const [scans, setScans] = useState([]);
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [viewPdfUrl, setViewPdfUrl] = useState(null);
  const [modalTitle, setModalTitle] = useState('');

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
        console.error('Failed to fetch reports:', err);
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
      
      // Method: standard browser download
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
      const pdfFile = new File([blob], fileName, { type: 'application/pdf' });
      const url = window.URL.createObjectURL(pdfFile);
      setViewPdfUrl(url);
    } catch (err) {
      console.error('View error:', err);
      alert('Failed to load PDF data');
    }
  };

  const closePdfModal = () => {
    setViewModalOpen(false);
  };

  const handleDelete = async (scanId) => {
    if (!window.confirm('Are you sure you want to permanently delete this report and scan history?')) return;
    try {
      await apiFetch(`/scans/${scanId}`, { method: 'DELETE' });
      setScans(scans.filter(s => s.id !== scanId));
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
      <main className="dashboard-main rp-main">
        <div className="dashboard-header mb-2">
          <div className="dashboard-header-left">
            <h1>Compliance Reports</h1>
            <p>View and download generated compliance audits for your repositories.</p>
          </div>
          <div className="dashboard-header-actions">
            <button className="btn-outline">
              <Filter size={16} />
              <span>Filter By Date</span>
            </button>
          </div>
        </div>

        {/* Available Reports Section */}
        <div className="rp-section">
          <h3 className="rp-section-title">Generated Reports</h3>
          
          {scans.length === 0 ? (
            <div className="rp-empty-state">
              <FileSearch size={48} />
              <h4>No reports generated yet</h4>
              <p>Reports will appear here after you perform a repository scan.</p>
              <button 
                className="btn-primary mt-1"
                onClick={() => navigate('/dashboard')}
              >
                Go to Dashboard
              </button>
            </div>
          ) : (
            <div className="rp-list">
              {scans.map((scan) => (
                <div className="rp-row-card" key={scan.id}>
                  <div className="rp-row-info">
                    <div className="rp-row-icon">
                      <FileText size={20} className="text-blue" />
                    </div>
                    <div className="rp-row-text">
                      <h4>DPDP Compliance Report - {scan.repo_name}</h4>
                      <p>
                        <span><Calendar size={12} /> {new Date(scan.created_at).toLocaleDateString()}</span>
                        <span className="mx-1">•</span>
                        <span>Score: {scan.score}/100</span>
                        <span className="mx-1">•</span>
                        <span className={`type-badge ${scan.compliance_data?.llm_pipeline?.deep_review ? 'deep' : 'standard'}`} style={{ marginLeft: '4px' }}>
                          {scan.compliance_data?.llm_pipeline?.deep_review ? 'DEEP AUDIT' : 'STANDARD'}
                        </span>
                      </p>
                    </div>
                  </div>
                  <div className="rp-row-actions">
                    <button 
                      className="rp-action-view" 
                      title="View Details"
                      onClick={() => handleView(scan)}
                      disabled={!scan.report_path}
                    >
                      <Eye size={18} />
                      <span>View</span>
                    </button>
                    <button 
                      className="rp-action-download" 
                      title="Download PDF"
                      onClick={() => handleDownload(scan)}
                      disabled={!scan.report_path}
                    >
                      <Download size={18} />
                      <span>Download</span>
                    </button>
                    <button 
                      className="rp-action-delete" 
                      title="Delete Report"
                      onClick={() => handleDelete(scan.id)}
                      style={{ border: 'none', background: 'none', cursor: 'pointer', color: '#ef4444', display: 'flex', alignItems: 'center', gap: '4px', padding: '8px', borderRadius: '6px' }}
                    >
                      <Trash2 size={18} />
                      <span>Delete</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
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
                  src={`${viewPdfUrl}#toolbar=0`} 
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
