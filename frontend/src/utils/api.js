/** Backend API origin (override with VITE_API_URL in frontend/.env) */
export const API_BASE_URL =
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function orgHeaders() {
  const orgId = localStorage.getItem('activeOrgId');
  return orgId ? { 'X-Org-Id': orgId } : {};
}

export async function apiFetch(endpoint, options = {}) {
  const token = localStorage.getItem('token');
  const headers = {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` }),
    ...orgHeaders(),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    localStorage.removeItem('token');
    window.location.href = '/login';
    return;
  }

  if (!response.ok) {
    let detail = 'API request failed';
    try {
      const error = await response.json();
      detail = error.detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }

  if (response.status === 204) return null;
  const ct = response.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    return response.json();
  }
  return response;
}

/** SSE-style streaming over fetch (bulk scan progress). */
export async function apiStream(endpoint, onMessage, options = {}) {
  const token = localStorage.getItem('token');
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      ...(token && { Authorization: `Bearer ${token}` }),
      ...orgHeaders(),
      ...options.headers,
    },
  });
  if (!response.ok) {
    throw new Error('Stream request failed');
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        try {
          onMessage(JSON.parse(line.slice(6)));
        } catch {
          /* ignore parse errors */
        }
      }
    }
  }
}
