import fs from 'fs';
import path from 'path';
import {
  NormalizedSecurityEvent,
  SecurityIncident,
  SecurityAlert,
  DataSource,
  AuditLogEntry,
  SOARPlaybook,
  ForensicArtifact,
} from './types';

// In-Memory Database Collections with Disk Backup
interface SentinelDB {
  events: NormalizedSecurityEvent[];
  alerts: SecurityAlert[];
  incidents: SecurityIncident[];
  dataSources: DataSource[];
  auditLogs: AuditLogEntry[];
  playbooks: SOARPlaybook[];
  artifacts: ForensicArtifact[];
}

const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'sentinelx-db.json');

// Initialize default Data Sources
const DEFAULT_DATA_SOURCES: DataSource[] = [
  {
    id: 'src-sysmon',
    name: 'Windows Sysmon & Security.evtx Forwarder',
    category: 'WINDOWS',
    description: 'Kernel process creation, DLL injection, pipe activity & event log forwarding.',
    status: 'CONNECTED',
    collectorType: 'WEF / Winlogbeat Agent',
    endpointUrl: '/api/events?collector=sysmon',
    authMethod: 'API_KEY',
    lastHeartbeat: new Date().toISOString(),
    eventsIngested: 142890,
    epsRate: 840,
    configSnippet: `# winlogbeat.yml configuration\nwinlogbeat.event_logs:\n  - name: Microsoft-Windows-Sysmon/Operational\noutput.elasticsearch:\n  hosts: ["https://sentinelx.corp.internal/api/events"]\n  headers:\n    Authorization: "Bearer sx-live-secops-token-8942"`,
  },
  {
    id: 'src-paloalto',
    name: 'Palo Alto PAN-OS NextGen Firewall',
    category: 'FIREWALL',
    description: 'Perimeter threat defense, URL filtering, GlobalProtect VPN & traffic drops.',
    status: 'CONNECTED',
    collectorType: 'Syslog UDP 514 / TLS Beat',
    endpointUrl: '/api/events?collector=paloalto',
    authMethod: 'SYSLOG_UDP',
    lastHeartbeat: new Date().toISOString(),
    eventsIngested: 894320,
    epsRate: 4200,
    configSnippet: `Device > Server Profiles > Syslog > Add\nServer: sentinelx-collector.corp.internal\nPort: 514 / Protocol: UDP\nFormat: BSD Syslog / Facility: LOG_USER`,
  },
  {
    id: 'src-crowdstrike',
    name: 'CrowdStrike Falcon / Microsoft Defender EDR',
    category: 'EDR',
    description: 'Real-time endpoint behavioral anomalies, process trees, and isolation webhook.',
    status: 'CONNECTED',
    collectorType: 'FDR Streaming API & Webhook',
    endpointUrl: '/api/events?collector=crowdstrike',
    authMethod: 'API_KEY',
    lastHeartbeat: new Date().toISOString(),
    eventsIngested: 45210,
    epsRate: 310,
    configSnippet: `curl -X POST https://sentinelx.corp.internal/api/events \\\n  -H "Authorization: Bearer sx-live-secops-token-8942" \\\n  -H "Content-Type: application/json" \\\n  -d '{"sourceType":"EDR", "hostname":"WS-01", "action":"DETECT", "processName":"mimikatz.exe"}'`,
  },
  {
    id: 'src-suricata',
    name: 'Suricata / Zeek Network IDS/IPS Sensor',
    category: 'IDS_IPS',
    description: 'Deep packet inspection, signature matching, C2 beacon detection & TLS SNI parser.',
    status: 'CONNECTED',
    collectorType: 'Suricata eve.json tailer',
    endpointUrl: '/api/events?collector=suricata',
    authMethod: 'TLS_BEAT',
    lastHeartbeat: new Date().toISOString(),
    eventsIngested: 512000,
    epsRate: 2850,
    configSnippet: `# suricata.yaml\noutputs:\n  - eve-log:\n      enabled: yes\n      type: file\n      filename: /var/log/suricata/eve.json\n# Filebeat forwards eve.json to /api/events`,
  },
  {
    id: 'src-linux-auditd',
    name: 'Linux Auditd & Auth.log Daemon',
    category: 'LINUX',
    description: 'Syscall execution monitoring, PAM authentication, sudo abuse, and rootkit detection.',
    status: 'CONNECTED',
    collectorType: 'Auditbeat / Rsyslog',
    endpointUrl: '/api/events?collector=linux-auditd',
    authMethod: 'AGENT',
    lastHeartbeat: new Date().toISOString(),
    eventsIngested: 78900,
    epsRate: 480,
    configSnippet: `auditctl -w /etc/passwd -p wa -k identity_tampering\nauditctl -w /bin/su -p x -k privilege_escalation`,
  },
  {
    id: 'src-coredns',
    name: 'CoreDNS / Active Directory DNS Sinkhole',
    category: 'DNS',
    description: 'Domain resolution telemetry, DGA detection, DNS tunneling exfiltration logs.',
    status: 'CONNECTED',
    collectorType: 'CoreDNS plugin log forwarder',
    endpointUrl: '/api/events?collector=dns',
    authMethod: 'API_KEY',
    lastHeartbeat: new Date().toISOString(),
    eventsIngested: 120400,
    epsRate: 920,
    configSnippet: `Corefile:\n. {\n    log . "{\\"timestamp\\":\\"{time}\\",\\"qname\\":\\"{name}\\",\\"qtype\\":\\"{type}\\",\\"client\\":\\"{remote}\\"}"\n    forward . 8.8.8.8\n}`,
  },
  {
    id: 'src-cloudtrail',
    name: 'AWS CloudTrail & Azure Activity Log',
    category: 'CLOUD',
    description: 'Cloud IAM role assumption, security group mutations, S3 bucket access.',
    status: 'NOT CONFIGURED',
    collectorType: 'AWS SNS / SQS Webhook',
    endpointUrl: '/api/events?collector=cloudtrail',
    authMethod: 'WEBHOOK',
    eventsIngested: 0,
    epsRate: 0,
    configSnippet: `AWS EventBridge Rule -> Target: HTTPS Webhook URL (https://sentinelx.corp.internal/api/events)`,
  },
  {
    id: 'src-rest-universal',
    name: 'Universal REST Ingestion API',
    category: 'APPLICATION',
    description: 'Direct log ingestion for custom SIEM agents, microservices, and scripts.',
    status: 'CONNECTED',
    collectorType: 'HTTP POST /api/events',
    endpointUrl: '/api/events',
    authMethod: 'API_KEY',
    lastHeartbeat: new Date().toISOString(),
    eventsIngested: 34200,
    epsRate: 150,
    configSnippet: `POST /api/events HTTP/1.1\nHost: sentinelx.corp.internal\nAuthorization: Bearer sx-live-secops-token-8942\nContent-Type: application/json\n\n[{"timestamp":"2026-08-19T10:00:00Z","sourceType":"WINDOWS","hostname":"DC01","message":"Kerberos ticket requested"}]`,
  },
];

const DEFAULT_PLAYBOOKS: SOARPlaybook[] = [
  {
    id: 'pb-isolate-host',
    name: 'Autonomous Endpoint Network Quarantine',
    description: 'Enforces EDR firewall isolation filter on host while preserving forensic telemetry connection to SentinelX.',
    category: 'CONTAINMENT',
    triggerType: 'MANUAL',
    targetSeverity: ['CRITICAL', 'HIGH'],
    requiresConfirmation: true,
    requiredIntegration: 'CrowdStrike / Defender EDR Sensor API',
    integrationStatus: 'AUTHORIZED',
    steps: [
      { id: '1', name: 'Verify Endpoint Online Status', action: 'ISOLATE_HOST', paramExample: '{HOST}', description: 'Checks EDR agent reachability and heartbeat' },
      { id: '2', name: 'Apply Host Quarantine Network Filter', action: 'ISOLATE_HOST', paramExample: 'NetFirewallRule -BlockAllExceptSentinelX', description: 'Blocks all outbound/inbound TCP/UDP except SOC agent port 8443' },
      { id: '3', name: 'Snapshot Volatile Process Memory', action: 'DUMP_MEMORY', paramExample: 'WinPmem.exe --output C:\\Forensics\\dump.raw', description: 'Captures full RAM snapshot for offline analysis' },
      { id: '4', name: 'Notify Tier-3 Incident Commander', action: 'NOTIFY_TEAM', paramExample: 'Slack #secops-alerts / PagerDuty P1', description: 'Dispatches emergency containment briefing' },
    ],
    executionCount: 14,
    lastExecuted: new Date(Date.now() - 3600000).toISOString(),
    enabled: true,
  },
  {
    id: 'pb-revoke-identity',
    name: 'Compromised Identity Invalidation & Token Revocation',
    category: 'IDENTITY',
    description: 'Purges active Kerberos TGT tickets, revokes OAuth2 tokens, and sets account status to locked.',
    triggerType: 'MANUAL',
    targetSeverity: ['CRITICAL', 'HIGH'],
    requiresConfirmation: true,
    requiredIntegration: 'Active Directory / Azure Entra ID Graph API',
    integrationStatus: 'AUTHORIZED',
    steps: [
      { id: '1', name: 'Purge Kerberos Ticket Cache', action: 'REVOKE_TOKEN', paramExample: 'klist purge -li 0x3e7', description: 'Flushes cached TGTs across domain' },
      { id: '2', name: 'Invalidate Active OAuth/SAML Refresh Tokens', action: 'REVOKE_TOKEN', paramExample: 'Revoke-AzureADUserAllRefreshToken', description: 'Forces re-authentication across all SaaS portals' },
      { id: '3', name: 'Apply Emergency Account Lockout', action: 'REVOKE_TOKEN', paramExample: 'Disable-ADAccount -Identity {USER}', description: 'Locks down interactive and service logon' },
    ],
    executionCount: 8,
    lastExecuted: new Date(Date.now() - 7200000).toISOString(),
    enabled: true,
  },
  {
    id: 'pb-block-c2-perimeter',
    name: 'Perimeter Firewall Dynamic Null-Route & C2 Block',
    category: 'NETWORK',
    description: 'Pushes malicious C2 IP and subnet indicators to border firewall blocklists and DNS sinkholes.',
    triggerType: 'AUTOMATIC',
    targetSeverity: ['CRITICAL'],
    requiresConfirmation: true,
    requiredIntegration: 'Palo Alto PAN-OS XML API',
    integrationStatus: 'AUTHORIZED',
    steps: [
      { id: '1', name: 'Validate IP Reputation & ASN', action: 'BLOCK_IP', paramExample: '{SOURCE_IP}', description: 'Confirms IP does not belong to essential CDNs' },
      { id: '2', name: 'Push IP to Palo Alto Dynamic Block List (DAG)', action: 'BLOCK_IP', paramExample: 'pan-os-api: /api/?type=op&cmd=<set-dag>', description: 'Instant perimeter drop across all edge gateways' },
      { id: '3', name: 'Inject DNS Sinkhole Response', action: 'BLOCK_IP', paramExample: 'CoreDNS sinkhole -> 0.0.0.0', description: 'Prevents internal hosts from resolving domain' },
    ],
    executionCount: 42,
    lastExecuted: new Date(Date.now() - 1800000).toISOString(),
    enabled: true,
  },
  {
    id: 'pb-kill-rogue-process',
    name: 'Rogue Child Process Tree Termination',
    category: 'HOST_DEFENSE',
    description: 'Terminates living-off-the-land processes, suspicious PowerShell spawns, and memory dumpers.',
    triggerType: 'MANUAL',
    targetSeverity: ['HIGH', 'MEDIUM'],
    requiresConfirmation: false,
    requiredIntegration: 'SentinelX Local Agent Daemon',
    integrationStatus: 'AUTHORIZED',
    steps: [
      { id: '1', name: 'Enumerate Process Handle Tree', action: 'KILL_PROCESS', paramExample: 'Get-ProcessTree -PID {PID}', description: 'Identifies parent-child relationships' },
      { id: '2', name: 'Force Kill Process Subtree', action: 'KILL_PROCESS', paramExample: 'taskkill /PID {PID} /T /F', description: 'Terminates rogue process and children' },
    ],
    executionCount: 29,
    lastExecuted: new Date(Date.now() - 900000).toISOString(),
    enabled: true,
  },
];

class DatabaseManager {
  private db: SentinelDB;

  constructor() {
    this.db = {
      events: [],
      alerts: [],
      incidents: [],
      dataSources: DEFAULT_DATA_SOURCES,
      auditLogs: [],
      playbooks: DEFAULT_PLAYBOOKS,
      artifacts: [],
    };
    this.loadFromDisk();
  }

  private loadFromDisk() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed) {
          this.db.events = parsed.events || [];
          this.db.alerts = parsed.alerts || [];
          this.db.incidents = parsed.incidents || [];
          this.db.auditLogs = parsed.auditLogs || [];
          if (parsed.dataSources?.length) this.db.dataSources = parsed.dataSources;
          if (parsed.playbooks?.length) this.db.playbooks = parsed.playbooks;
          if (parsed.artifacts?.length) this.db.artifacts = parsed.artifacts;
        }
      }
    } catch (err) {
      console.warn('Failed to load database from disk, using in-memory store:', err);
    }
  }

  public saveToDisk() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      // Cap events in storage to keep file fast
      const snapshot: SentinelDB = {
        ...this.db,
        events: this.db.events.slice(0, 1000),
        alerts: this.db.alerts.slice(0, 500),
        incidents: this.db.incidents.slice(0, 100),
        auditLogs: this.db.auditLogs.slice(0, 300),
      };
      fs.writeFileSync(DB_FILE, JSON.stringify(snapshot, null, 2), 'utf-8');
    } catch (err) {
      console.warn('Failed to save DB to disk:', err);
    }
  }

  // Events Operations
  public addEvent(event: NormalizedSecurityEvent) {
    this.db.events.unshift(event);
    if (this.db.events.length > 5000) {
      this.db.events = this.db.events.slice(0, 5000);
    }
    // Update data source metrics
    const ds = this.db.dataSources.find((d) => d.category === event.sourceType || d.collectorType.includes(event.sourceType));
    if (ds) {
      ds.eventsIngested += 1;
      ds.lastHeartbeat = new Date().toISOString();
      ds.status = 'CONNECTED';
    }
  }

  public getEvents(limit = 100, filter?: { sourceType?: string; severity?: string; query?: string; isDemo?: boolean }) {
    let result = this.db.events;
    if (filter) {
      if (filter.isDemo !== undefined) {
        result = result.filter((e) => !!e.isDemo === filter.isDemo);
      }
      if (filter.sourceType && filter.sourceType !== 'ALL') {
        result = result.filter((e) => e.sourceType === filter.sourceType);
      }
      if (filter.severity && filter.severity !== 'ALL') {
        result = result.filter((e) => e.severity === filter.severity);
      }
      if (filter.query) {
        const q = filter.query.toLowerCase();
        result = result.filter(
          (e) =>
            e.sourceIp.toLowerCase().includes(q) ||
            e.destinationIp.toLowerCase().includes(q) ||
            e.hostname.toLowerCase().includes(q) ||
            (e.user && e.user.toLowerCase().includes(q)) ||
            (e.processName && e.processName.toLowerCase().includes(q)) ||
            (e.commandLine && e.commandLine.toLowerCase().includes(q)) ||
            e.message.toLowerCase().includes(q) ||
            (e.hashes?.sha256 && e.hashes.sha256.toLowerCase().includes(q))
        );
      }
    }
    return result.slice(0, limit);
  }

  // Alerts Operations
  public addAlert(alert: SecurityAlert) {
    this.db.alerts.unshift(alert);
    if (this.db.alerts.length > 1000) {
      this.db.alerts = this.db.alerts.slice(0, 1000);
    }
  }

  public getAlerts(limit = 50, isDemo?: boolean) {
    let list = this.db.alerts;
    if (isDemo !== undefined) {
      list = list.filter((a) => !!a.isDemo === isDemo);
    }
    return list.slice(0, limit);
  }

  // Incidents Operations
  public addIncident(incident: SecurityIncident) {
    const existingIdx = this.db.incidents.findIndex((i) => i.id === incident.id);
    if (existingIdx >= 0) {
      this.db.incidents[existingIdx] = incident;
    } else {
      this.db.incidents.unshift(incident);
    }
    this.saveToDisk();
  }

  public updateIncident(incident: SecurityIncident) {
    this.db.incidents = this.db.incidents.map((i) => (i.id === incident.id ? incident : i));
    this.saveToDisk();
  }

  public getIncidents(isDemo?: boolean) {
    if (isDemo !== undefined) {
      return this.db.incidents.filter((i) => !!i.isDemo === isDemo);
    }
    return this.db.incidents;
  }

  public getIncidentById(id: string) {
    return this.db.incidents.find((i) => i.id === id);
  }

  // Data Sources
  public getDataSources() {
    return this.db.dataSources;
  }

  public updateDataSourceStatus(id: string, status: DataSource['status'], errorMsg?: string) {
    this.db.dataSources = this.db.dataSources.map((ds) =>
      ds.id === id ? { ...ds, status, errorMessage: errorMsg, lastHeartbeat: new Date().toISOString() } : ds
    );
    this.saveToDisk();
  }

  // Audit Logs
  public addAuditLog(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>) {
    const log: AuditLogEntry = {
      id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: new Date().toISOString(),
      ...entry,
    };
    this.db.auditLogs.unshift(log);
    if (this.db.auditLogs.length > 500) {
      this.db.auditLogs = this.db.auditLogs.slice(0, 500);
    }
    this.saveToDisk();
    return log;
  }

  public getAuditLogs(limit = 100) {
    return this.db.auditLogs.slice(0, limit);
  }

  // Playbooks
  public getPlaybooks() {
    return this.db.playbooks;
  }

  public updatePlaybook(updated: SOARPlaybook) {
    this.db.playbooks = this.db.playbooks.map((pb) => (pb.id === updated.id ? updated : pb));
    this.saveToDisk();
  }

  // Real-time System Telemetry Metrics
  public getSystemStats(isDemo = false) {
    const incs = this.getIncidents(isDemo);
    const criticalCount = incs.filter((i) => i.severity === 'CRITICAL').length;
    const openCount = incs.filter((i) => i.status === 'OPEN' || i.status === 'INVESTIGATING').length;
    const totalEvents = this.db.events.filter((e) => !!e.isDemo === isDemo).length;
    const liveSourcesConnected = this.db.dataSources.filter((d) => d.status === 'CONNECTED').length;
    const totalEPS = this.db.dataSources.reduce((acc, d) => acc + (d.status === 'CONNECTED' ? d.epsRate : 0), 0);

    return {
      criticalCount,
      openCount,
      totalIncidents: incs.length,
      totalEvents,
      liveSourcesConnected,
      totalDataSources: this.db.dataSources.length,
      totalEPS: totalEPS || (isDemo ? 14892 : 0),
      autonomousBlocks: this.db.auditLogs.filter((a) => a.action.includes('Quarantine') || a.action.includes('Block')).length + (isDemo ? 173 : 0),
    };
  }
}

export const dbManager = new DatabaseManager();
