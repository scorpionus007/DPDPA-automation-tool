import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import DashboardLayout from '../../layouts/DashboardLayout';
import { apiFetch } from '../../utils/api';
import { useOrg } from '../../contexts/OrgContext';

export default function OrgRepoListPage() {
  const { activeOrgId } = useOrg();
  const navigate = useNavigate();
  const [repos, setRepos] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [search, setSearch] = useState('');
  const [langFilter, setLangFilter] = useState('');
  const [privateFilter, setPrivateFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    if (!activeOrgId) return;
    (async () => {
      setLoading(true);
      try {
        const data = await apiFetch(`/orgs/${activeOrgId}/repositories?refresh=true`);
        setRepos(data || []);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    })();
  }, [activeOrgId]);

  const languages = useMemo(() => {
    const set = new Set(repos.map((r) => r.language).filter(Boolean));
    return [...set].sort();
  }, [repos]);

  const filtered = useMemo(() => {
    return repos.filter((r) => {
      if (search && !r.full_name.toLowerCase().includes(search.toLowerCase())) return false;
      if (langFilter && r.language !== langFilter) return false;
      if (privateFilter === 'private' && !r.private) return false;
      if (privateFilter === 'public' && r.private) return false;
      return true;
    });
  }, [repos, search, langFilter, privateFilter]);

  const toggle = (id) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  const selectAll = () => setSelected(new Set(filtered.map((r) => r.id)));
  const clearAll = () => setSelected(new Set());

  const startScan = async (mode) => {
    if (!selected.size) return;
    setScanning(true);
    try {
      const batch = await apiFetch(`/orgs/${activeOrgId}/bulk-scan`, {
        method: 'POST',
        body: JSON.stringify({ repository_ids: [...selected], scan_mode: mode }),
      });
      navigate(`/org/scans?batch=${batch.id}`);
    } catch (e) {
      alert(e.message);
    } finally {
      setScanning(false);
    }
  };

  if (!activeOrgId) {
    return (
      <DashboardLayout title="Organization Repositories">
        <p>Connect an organization first.</p>
        <button type="button" onClick={() => navigate('/org/connect')}>Connect Org</button>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Organization Repositories">
      <div className="toolbar" style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
        <input
          placeholder="Search repos..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, minWidth: 200, padding: 8 }}
        />
        <select value={langFilter} onChange={(e) => setLangFilter(e.target.value)}>
          <option value="">All languages</option>
          {languages.map((l) => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>
        <select value={privateFilter} onChange={(e) => setPrivateFilter(e.target.value)}>
          <option value="all">All visibility</option>
          <option value="private">Private only</option>
          <option value="public">Public only</option>
        </select>
        <button type="button" onClick={selectAll}>Select filtered</button>
        <button type="button" onClick={clearAll}>Clear</button>
        <button type="button" disabled={!selected.size || scanning} onClick={() => startScan('fast')}>
          Fast scan ({selected.size})
        </button>
        <button type="button" disabled={!selected.size || scanning} onClick={() => startScan('deep')}>
          Deep scan ({selected.size})
        </button>
      </div>
      {loading ? (
        <p>Loading repositories...</p>
      ) : (
        <table style={{ width: '100%' }}>
          <thead>
            <tr>
              <th></th>
              <th>Repository</th>
              <th>Language</th>
              <th>Score</th>
              <th>Last scan</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.id}>
                <td>
                  <input
                    type="checkbox"
                    checked={selected.has(r.id)}
                    onChange={() => toggle(r.id)}
                  />
                </td>
                <td>{r.full_name}{r.private ? ' 🔒' : ''}</td>
                <td>{r.language || '—'}</td>
                <td>{r.last_score ?? '—'}</td>
                <td>{r.last_scan_at ? new Date(r.last_scan_at).toLocaleDateString() : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </DashboardLayout>
  );
}
