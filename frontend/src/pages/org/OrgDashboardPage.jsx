import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import DashboardLayout from '../../layouts/DashboardLayout';
import { apiFetch } from '../../utils/api';
import { useOrg } from '../../contexts/OrgContext';

export default function OrgDashboardPage() {
  const { activeOrgId } = useOrg();
  const [stats, setStats] = useState(null);

  useEffect(() => {
    if (!activeOrgId) return;
    apiFetch(`/orgs/${activeOrgId}/dashboard`)
      .then(setStats)
      .catch(console.error);
  }, [activeOrgId]);

  if (!activeOrgId) {
    return (
      <DashboardLayout title="Organization Dashboard">
        <p>
          <Link to="/org/connect">Connect a GitHub Organization</Link> to get started.
        </p>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Organization Dashboard">
      {!stats ? (
        <p>Loading...</p>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 16 }}>
            <StatCard label="Org Score" value={`${stats.score}/100 (${stats.grade})`} />
            <StatCard label="Repos Total" value={stats.reposTotal} />
            <StatCard label="Repos Scanned" value={stats.reposScanned} />
            <StatCard label="PII Entities" value={stats.entityCount} />
            <StatCard label="Cross-Repo Edges" value={stats.edgeCount} />
          </div>
          <h3 style={{ marginTop: 24 }}>Top cross-cutting risks</h3>
          <ul>
            {(stats.topRisks || []).map((r) => (
              <li key={r.rule}>
                {r.rule} — <strong>{r.repoCount}</strong> repos
              </li>
            ))}
          </ul>
          <h3 style={{ marginTop: 24 }}>Repository scores</h3>
          <table style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>Repo</th>
                <th>Score</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {(stats.repoScores || []).map((r) => (
                <tr key={r.repoId || r.repoName}>
                  <td>{r.repoName}</td>
                  <td>{r.score}</td>
                  <td>{r.scannedAt ? new Date(r.scannedAt).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </DashboardLayout>
  );
}

function StatCard({ label, value }) {
  return (
    <div style={{ background: '#1e293b', padding: 16, borderRadius: 8 }}>
      <p style={{ fontSize: 12, opacity: 0.7, margin: 0 }}>{label}</p>
      <p style={{ fontSize: 22, fontWeight: 600, margin: '4px 0 0' }}>{value}</p>
    </div>
  );
}
