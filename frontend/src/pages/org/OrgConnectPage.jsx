import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Building2, ExternalLink } from 'lucide-react';
import DashboardLayout from '../../layouts/DashboardLayout';
import { API_BASE_URL } from '../../utils/api';
import { useOrg } from '../../contexts/OrgContext';

export default function OrgConnectPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { refreshOrgs, setActiveOrgId } = useOrg();
  const error = params.get('error');
  const orgId = params.get('org_id');

  useEffect(() => {
    if (orgId) {
      setActiveOrgId(parseInt(orgId, 10));
      refreshOrgs().then(() => navigate('/org/repos'));
    }
  }, [orgId]);

  const connect = () => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }
    window.location.href = `${API_BASE_URL}/orgs/connect?token=${encodeURIComponent(token)}`;
  };

  return (
    <DashboardLayout title="Connect GitHub Organization">
      <div className="card" style={{ maxWidth: 560, padding: 24 }}>
        <Building2 size={48} style={{ marginBottom: 16 }} />
        <h2>Install GitHub App</h2>
        <p style={{ marginBottom: 16, lineHeight: 1.6 }}>
          Connect your GitHub Organization to mass-scan all repositories, build a cross-repo
          entity knowledge base, and generate organization-wide compliance reports.
        </p>
        {error && <p style={{ color: '#f87171' }}>Error: {error}</p>}
        <button type="button" className="btn-primary" onClick={connect}>
          <ExternalLink size={16} style={{ marginRight: 8 }} />
          Install on GitHub
        </button>
      </div>
    </DashboardLayout>
  );
}
