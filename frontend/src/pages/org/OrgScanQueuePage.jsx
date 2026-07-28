import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import DashboardLayout from '../../layouts/DashboardLayout';
import { apiFetch, apiStream } from '../../utils/api';
import { useOrg } from '../../contexts/OrgContext';

export default function OrgScanQueuePage() {
  const { activeOrgId } = useOrg();
  const [params] = useSearchParams();
  const batchId = params.get('batch');
  const [batch, setBatch] = useState(null);
  const [expandedError, setExpandedError] = useState(null);

  useEffect(() => {
    if (!activeOrgId || !batchId) return;
    let cancelled = false;

    const poll = async () => {
      try {
        const data = await apiFetch(`/orgs/${activeOrgId}/bulk-scan/${batchId}`);
        if (!cancelled) setBatch(data);
      } catch (e) {
        console.error(e);
      }
    };

    poll();
    const streamUrl = `/orgs/${activeOrgId}/bulk-scan/${batchId}/stream`;
    apiStream(streamUrl, (msg) => {
      if (!msg.error) setBatch(msg);
    }).catch(() => {
      const iv = setInterval(poll, 3000);
      return () => clearInterval(iv);
    });

    return () => {
      cancelled = true;
    };
  }, [activeOrgId, batchId]);

  const retry = async (jobId) => {
    await apiFetch(`/orgs/${activeOrgId}/bulk-scan/jobs/${jobId}/retry`, { method: 'POST' });
    const data = await apiFetch(`/orgs/${activeOrgId}/bulk-scan/${batchId}`);
    setBatch(data);
  };

  const cancel = async () => {
    await apiFetch(`/orgs/${activeOrgId}/bulk-scan/${batchId}/cancel`, { method: 'POST' });
    const data = await apiFetch(`/orgs/${activeOrgId}/bulk-scan/${batchId}`);
    setBatch(data);
  };

  if (!batchId) {
    return (
      <DashboardLayout title="Bulk Scan Queue">
        <p>No batch selected. Start a scan from Org Repos.</p>
      </DashboardLayout>
    );
  }

  const progress = batch
    ? Math.round(((batch.succeeded + batch.failed) / Math.max(batch.total, 1)) * 100)
    : 0;

  return (
    <DashboardLayout title="Bulk Scan Queue">
      {batch && (
        <>
          <p>
            Status: <strong>{batch.status}</strong> — {batch.succeeded}/{batch.total} done (
            {batch.failed} failed) — mode: {batch.scan_mode}
          </p>
          <div style={{ background: '#334155', borderRadius: 4, height: 8, marginBottom: 16 }}>
            <div
              style={{
                width: `${progress}%`,
                height: '100%',
                background: '#38bdf8',
                borderRadius: 4,
              }}
            />
          </div>
          {batch.status === 'running' && (
            <button type="button" onClick={cancel} style={{ marginBottom: 16 }}>
              Cancel batch
            </button>
          )}
          <table style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>Repository</th>
                <th>Status</th>
                <th>Scan</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(batch.jobs || []).map((j) => (
                <tr key={j.id}>
                  <td>{j.repo_full_name}</td>
                  <td>{j.status}</td>
                  <td>{j.scan_id ? `#${j.scan_id}` : '—'}</td>
                  <td>
                    {j.status === 'failed' && (
                      <>
                        <button type="button" onClick={() => retry(j.id)}>Retry</button>
                        <button
                          type="button"
                          onClick={() => setExpandedError(expandedError === j.id ? null : j.id)}
                        >
                          Error
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {expandedError && (
            <pre style={{ marginTop: 16, padding: 12, background: '#1e293b', overflow: 'auto' }}>
              {batch.jobs.find((j) => j.id === expandedError)?.error}
            </pre>
          )}
        </>
      )}
      {!batch && <p>Loading batch...</p>}
    </DashboardLayout>
  );
}
