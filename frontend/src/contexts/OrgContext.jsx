import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { apiFetch } from '../utils/api';

const OrgContext = createContext(null);

const STORAGE_KEY = 'activeOrgId';

export function OrgProvider({ children }) {
  const [orgs, setOrgs] = useState([]);
  const [activeOrgId, setActiveOrgIdState] = useState(() => {
    const v = localStorage.getItem(STORAGE_KEY);
    return v ? parseInt(v, 10) : null;
  });
  const [loading, setLoading] = useState(true);

  const refreshOrgs = useCallback(async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      setOrgs([]);
      setLoading(false);
      return;
    }
    try {
      const list = await apiFetch('/orgs');
      setOrgs(list || []);
      if (list?.length && !list.find((o) => o.id === activeOrgId)) {
        const first = list[0].id;
        setActiveOrgIdState(first);
        localStorage.setItem(STORAGE_KEY, String(first));
      }
    } catch (e) {
      console.error('Failed to load orgs', e);
    } finally {
      setLoading(false);
    }
  }, [activeOrgId]);

  useEffect(() => {
    refreshOrgs();
  }, []);

  const setActiveOrgId = (id) => {
    setActiveOrgIdState(id);
    if (id != null) {
      localStorage.setItem(STORAGE_KEY, String(id));
      localStorage.setItem('activeOrgId', String(id));
    } else {
      localStorage.removeItem(STORAGE_KEY);
      localStorage.removeItem('activeOrgId');
    }
  };

  const activeOrg = orgs.find((o) => o.id === activeOrgId) || null;

  return (
    <OrgContext.Provider
      value={{
        orgs,
        activeOrg,
        activeOrgId,
        setActiveOrgId,
        refreshOrgs,
        loading,
      }}
    >
      {children}
    </OrgContext.Provider>
  );
}

export function useOrg() {
  const ctx = useContext(OrgContext);
  if (!ctx) throw new Error('useOrg must be used within OrgProvider');
  return ctx;
}
