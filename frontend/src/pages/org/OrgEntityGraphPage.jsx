import { useCallback, useEffect, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useEdgesState,
  useNodesState,
} from 'reactflow';
import 'reactflow/dist/style.css';
import DashboardLayout from '../../layouts/DashboardLayout';
import { apiFetch } from '../../utils/api';
import { useOrg } from '../../contexts/OrgContext';

export default function OrgEntityGraphPage() {
  const { activeOrgId } = useOrg();
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [entities, setEntities] = useState([]);
  const [drawer, setDrawer] = useState(null);

  const loadGraph = useCallback(async () => {
    if (!activeOrgId) return;
    const [flowData, entityData] = await Promise.all([
      apiFetch(`/orgs/${activeOrgId}/data-flows`),
      apiFetch(`/orgs/${activeOrgId}/entities?limit=50`),
    ]);
    setEntities(entityData || []);

    const repoSet = new Set();
    (flowData || []).forEach((e) => {
      repoSet.add(e.src_repo_name);
      repoSet.add(e.dst_repo_name);
    });
    const repoList = [...repoSet];
    const nodeMap = {};
    repoList.forEach((name, i) => {
      const col = i % 4;
      const row = Math.floor(i / 4);
      nodeMap[name] = {
        id: name,
        data: { label: name },
        position: { x: col * 280, y: row * 120 },
        style: {
          background: '#1e293b',
          color: '#e2e8f0',
          border: '1px solid #475569',
          padding: 8,
          borderRadius: 6,
          fontSize: 11,
          maxWidth: 200,
        },
      };
    });
    const edgeList = (flowData || []).map((e, idx) => ({
      id: `e-${idx}`,
      source: e.src_repo_name,
      target: e.dst_repo_name,
      label: e.entity_name,
      animated: true,
      style: { stroke: '#38bdf8' },
      labelStyle: { fill: '#94a3b8', fontSize: 10 },
    }));
    setNodes(Object.values(nodeMap));
    setEdges(edgeList);
  }, [activeOrgId, setNodes, setEdges]);

  useEffect(() => {
    loadGraph().catch(console.error);
  }, [loadGraph]);

  const openEntity = async (entityId) => {
    const detail = await apiFetch(`/orgs/${activeOrgId}/entities/${entityId}`);
    setDrawer(detail);
  };

  return (
    <DashboardLayout title="Cross-Repo Data Flows">
      <div style={{ display: 'flex', gap: 16, height: 'calc(100vh - 180px)' }}>
        <div style={{ width: 260, overflow: 'auto' }}>
          <h3>Entities</h3>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {entities.map((ent) => (
              <li key={ent.id} style={{ marginBottom: 8 }}>
                <button type="button" onClick={() => openEntity(ent.id)}>
                  {ent.canonical_name} ({ent.repo_count} repos)
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div style={{ flex: 1, border: '1px solid #334155', borderRadius: 8 }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
          >
            <Background />
            <Controls />
            <MiniMap />
          </ReactFlow>
        </div>
        {drawer && (
          <div
            style={{
              width: 320,
              background: '#1e293b',
              padding: 16,
              borderRadius: 8,
              overflow: 'auto',
            }}
          >
            <button type="button" onClick={() => setDrawer(null)}>Close</button>
            <h3>{drawer.entity?.canonical_name}</h3>
            <p>Kind: {drawer.entity?.kind}</p>
            <h4>Occurrences</h4>
            <ul>
              {(drawer.occurrences || []).slice(0, 20).map((o) => (
                <li key={o.id} style={{ marginBottom: 8, fontSize: 12 }}>
                  <strong>{o.repo_full_name}</strong> [{o.role}]
                  <br />
                  {o.file_path}
                  {o.snippet && (
                    <pre style={{ fontSize: 10, marginTop: 4, overflow: 'auto' }}>
                      {o.snippet.slice(0, 200)}
                    </pre>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
