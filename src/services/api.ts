import {
  SecurityIncident,
  ForensicArtifact,
  ChatMessage,
  NormalizedSecurityEvent,
  SecurityAlert,
  DataSource,
  AuditLogEntry,
  SOARPlaybook,
  IOCItem,
} from '../types';

export async function fetchHealth() {
  const res = await fetch('/api/health');
  return res.json();
}

// Ingestion API
export async function ingestSecurityLog(payload: any, apiKey = 'sx-live-secops-token-8942') {
  const res = await fetch('/api/events', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to ingest log');
  }
  return res.json();
}

// Events Query & Hunting
export async function fetchEvents(params?: {
  limit?: number;
  sourceType?: string;
  severity?: string;
  q?: string;
  isDemo?: boolean;
}) {
  const query = new URLSearchParams();
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.sourceType) query.set('sourceType', params.sourceType);
  if (params?.severity) query.set('severity', params.severity);
  if (params?.q) query.set('q', params.q);
  if (params?.isDemo !== undefined) query.set('isDemo', String(params.isDemo));

  const res = await fetch(`/api/events?${query.toString()}`);
  return res.json();
}

// Alerts Query
export async function fetchAlerts(isDemo?: boolean) {
  const query = isDemo !== undefined ? `?isDemo=${isDemo}` : '';
  const res = await fetch(`/api/alerts${query}`);
  return res.json();
}

// Incidents Query & Mutate
export async function fetchIncidents(isDemo?: boolean) {
  const query = isDemo !== undefined ? `?isDemo=${isDemo}` : '';
  const res = await fetch(`/api/incidents${query}`);
  return res.json();
}

export async function fetchIncidentById(id: string) {
  const res = await fetch(`/api/incidents/${id}`);
  return res.json();
}

export async function updateIncidentStatus(
  id: string,
  update: { status?: string; remediationAction?: string; executedBy?: string; output?: string }
) {
  const res = await fetch(`/api/incidents/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(update),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to update incident');
  }
  return res.json();
}

// Data Sources
export async function fetchDataSources(): Promise<{ success: boolean; dataSources: DataSource[]; activeIngestKey: string }> {
  const res = await fetch('/api/data-sources');
  return res.json();
}

export async function testDataSource(id: string) {
  const res = await fetch(`/api/data-sources/${id}/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to trigger data source diagnostic test');
  }
  return res.json();
}

// IOC Enrichment
export async function enrichIOC(type: string, value: string): Promise<{ success: boolean; ioc: IOCItem }> {
  const res = await fetch(`/api/ioc/enrich?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to enrich IOC');
  }
  return res.json();
}

// Stats & Audit Logs
export async function fetchSystemStats(isDemo = false) {
  const res = await fetch(`/api/stats?isDemo=${isDemo}`);
  return res.json();
}

export async function fetchAuditLogs(limit = 100): Promise<{ success: boolean; auditLogs: AuditLogEntry[] }> {
  const res = await fetch(`/api/audit-logs?limit=${limit}`);
  return res.json();
}

// Playbooks
export async function fetchPlaybooks(): Promise<{ success: boolean; playbooks: SOARPlaybook[] }> {
  const res = await fetch('/api/playbooks');
  return res.json();
}

export async function executeSOARPlaybook(
  playbookId: string,
  params: { incidentId?: string; confirmed: boolean; analystNotes?: string; executedBy?: string }
) {
  const res = await fetch(`/api/playbooks/${playbookId}/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to execute SOAR playbook');
  }
  return res.json();
}

// AI Services
export async function investigateIncidentWithAI(incident: SecurityIncident) {
  const response = await fetch('/api/ai/investigate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ incident }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to analyze incident with AI');
  }
  return response.json();
}

export async function analyzeArtifactWithAI(artifact: ForensicArtifact) {
  const response = await fetch('/api/ai/analyze-forensic-artifact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ artifact }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to analyze artifact with AI');
  }
  return response.json();
}

export async function generateDetectionRuleWithAI(params: {
  format: string;
  targetDescription: string;
  sampleCode?: string;
  severity?: string;
}) {
  const response = await fetch('/api/ai/generate-rule', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to generate detection rule');
  }
  return response.json();
}

export async function sendCopilotMessage(messages: ChatMessage[], contextData?: any) {
  const response = await fetch('/api/ai/copilot-chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages, contextData }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to send copilot message');
  }
  return response.json();
}

export async function generateFullForensicReport(incident: SecurityIncident, artifacts: ForensicArtifact[]) {
  const response = await fetch('/api/ai/forensic-report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ incident, artifacts }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to generate forensic report');
  }
  return response.json();
}
