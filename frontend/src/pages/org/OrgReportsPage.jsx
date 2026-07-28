import { useEffect, useState } from 'react';
import DashboardLayout from '../../layouts/DashboardLayout';
import { apiFetch, API_BASE_URL } from '../../utils/api';
import { useOrg } from '../../contexts/OrgContext';

export default function OrgReportsPage() {
  const { activeOrgId } = useOrg();
  const [reports, setReports] = useState([]);
  const [generating, setGenerating] = useState(false);

  const load = () => {
    if (!activeOrgId) return;
    apiFetch(`/orgs/${activeOrgId}/reports`).then(setReports).catch(console.error);
  };

  useEffect(load, [activeOrgId]);

  const generate = async () => {
    setGenerating(true);
    try {
      await apiFetch(`/orgs/${activeOrgId}/reports/generate`, { method: 'POST' });
      load();
    } catch (e) {
      alert(e.message);
    } finally {
      setGenerating(false);
    }
  };

  const download = (id, format = 'pdf') => {
    const token = localStorage.getItem('token');
    const orgId = localStorage.getItem('activeOrgId');
    window.open(
      `${API_BASE_URL}/orgs/${orgId}/reports/${id}?format=${format}&download=true&token=${token}`,
      '_blank'
    );
  };

  return (
    <DashboardLayout title="Organization Reports">
      <button type="button" disabled={generating || !activeOrgId} onClick={generate}>
        {generating ? 'Generating...' : 'Generate org-wide report'}
      </button>
      <table style={{ width: '100%', marginTop: 24 }}>
        <thead>
          <tr>
            <th>ID</th>
            <th>Status</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {reports.map((r) => (
            <tr key={r.id}>
              <td>{r.id}</td>
              <td>{r.status}</td>
              <td>{r.created_at ? new Date(r.created_at).toLocaleString() : '—'}</td>
              <td>
                {r.status === 'completed' && (
                  <>
                    <button type="button" onClick={() => download(r.id, 'pdf')}>PDF</button>
                    <button type="button" onClick={() => download(r.id, 'html')}>HTML</button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </DashboardLayout>
  );
}
