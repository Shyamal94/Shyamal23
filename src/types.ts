export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'REMEDIATED' | 'CLOSED';
export type ArtifactType = 'PCAP_DUMP' | 'MEMORY_SNAPSHOT' | 'POWERSHELL_PAYLOAD' | 'EVENT_LOG_EVTX' | 'REGISTRY_HIVE' | 'ELF_BINARY_HEX' | 'MACRO_DOCUMENT';
export type RuleFormat = 'YARA' | 'SIGMA' | 'SURICATA' | 'KQL';
export type DataSourceStatus = 'CONNECTED' | 'DISCONNECTED' | 'ERROR' | 'NOT CONFIGURED';
export type SourceCategory = 'WINDOWS' | 'LINUX' | 'FIREWALL' | 'IDS_IPS' | 'EDR' | 'DNS' | 'APPLICATION' | 'CLOUD';
export type UserRole = 'SOC_ADMIN' | 'TIER_3_ANALYST' | 'TIER_1_TRIAGE' | 'INCIDENT_COMMANDER';

export interface IOCItem {
  type: 'IP' | 'DOMAIN' | 'HASH_SHA256' | 'HASH_MD5' | 'FILE_PATH' | 'REGISTRY_KEY' | 'MUTEX' | 'URL' | 'CVE';
  value: string;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'UNKNOWN' | 'BENIGN';
  firstSeen?: string;
  sourceContext?: string;
  geo?: { country: string; city: string; lat: number; lng: number; flag: string };
  threatActor?: string;
  cveData?: {
    cveId: string;
    cvss: number;
    epss: number;
    description: string;
  };
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  phase: string;
  source: string;
  summary: string;
  details: string;
  severity: ThreatSeverity;
  tactics?: string[];
}

export interface SecurityIncident {
  id: string;
  title: string;
  description: string;
  category: 'RANSOMWARE' | 'LATERAL_MOVEMENT' | 'C2_BEACON' | 'CREDENTIAL_DUMPING' | 'EXFILTRATION' | 'ZERO_DAY_EXPLOIT' | 'INSIDER_THREAT' | 'SUSPICIOUS_EXECUTION' | 'BRUTE_FORCE' | 'DNS_TUNNELING';
  severity: ThreatSeverity;
  status: IncidentStatus;
  sourceIp: string;
  sourceGeo: { country: string; city: string; lat: number; lng: number; flag: string };
  targetHost: string;
  targetUser: string;
  mitreTactic: string;
  mitreTechnique: string;
  mitreId: string;
  timestamp: string;
  anomalyScore: number; // 0 to 100
  confidenceScore: number; // 0 to 100
  affectedAssets: string[];
  rawLogs: string[];
  iocs: IOCItem[];
  timelineEvents: TimelineEvent[];
  isDemo?: boolean;
  aiAnalysis?: {
    rootCause: string;
    blastRadius: string;
    threatActorProfile: string;
    technicalSummary: string;
    containmentSteps: string[];
    remediationScript: string;
    generatedDetectionRule?: string;
  };
  remediationHistory: Array<{
    id: string;
    action: string;
    executedBy: string;
    timestamp: string;
    status: 'SUCCESS' | 'IN_PROGRESS' | 'FAILED';
    output: string;
  }>;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  source: string;
  severity: ThreatSeverity;
  eventCode: string;
  message: string;
  sourceIp: string;
  destinationIp: string;
  processName?: string;
  user?: string;
  category: string;
  isDemo?: boolean;
}

export interface NormalizedSecurityEvent {
  id: string;
  timestamp: string;
  sourceType: SourceCategory;
  sourceCollector: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  hostname: string;
  user?: string;
  processName?: string;
  processId?: number;
  parentProcessName?: string;
  commandLine?: string;
  eventId?: string | number;
  action: 'ALLOW' | 'BLOCK' | 'DROP' | 'DETECT' | 'EXECUTE' | 'AUTH_SUCCESS' | 'AUTH_FAILURE' | 'FILE_WRITE' | 'DNS_QUERY';
  status: 'SUCCESS' | 'FAILURE' | 'SUSPICIOUS' | 'BLOCKED';
  message: string;
  rawLog: string;
  hashes?: {
    sha256?: string;
    md5?: string;
  };
  geo?: {
    country: string;
    city: string;
    lat: number;
    lng: number;
    flag: string;
  };
  severity: ThreatSeverity;
  riskScore: number;
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreId?: string;
  isDemo?: boolean;
}

export interface DataSource {
  id: string;
  name: string;
  category: SourceCategory;
  description: string;
  status: DataSourceStatus;
  collectorType: string;
  endpointUrl?: string;
  authMethod: 'API_KEY' | 'SYSLOG_UDP' | 'TLS_BEAT' | 'WEBHOOK' | 'AGENT';
  lastHeartbeat?: string;
  eventsIngested: number;
  epsRate: number;
  configSnippet: string;
  errorMessage?: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  userId: string;
  userRole: string;
  action: string;
  target: string;
  details: string;
  status: 'SUCCESS' | 'DENIED' | 'FAILED';
  clientIp?: string;
}

export interface SOARPlaybook {
  id: string;
  name: string;
  description: string;
  category: string;
  triggerType: 'AUTOMATIC' | 'MANUAL';
  targetSeverity: ThreatSeverity[];
  requiresConfirmation?: boolean;
  requiredIntegration?: string;
  integrationStatus?: 'AUTHORIZED' | 'PENDING_CONFIG' | 'UNAUTHORIZED';
  steps: Array<{
    id: string;
    name: string;
    action: 'ISOLATE_HOST' | 'KILL_PROCESS' | 'REVOKE_TOKEN' | 'BLOCK_IP' | 'DUMP_MEMORY' | 'SCAN_YARA' | 'NOTIFY_TEAM';
    paramExample: string;
    description: string;
  }>;
  executionCount: number;
  lastExecuted?: string;
  enabled: boolean;
}

export interface ForensicArtifact {
  id: string;
  name: string;
  artifactType: ArtifactType;
  fileSize: string;
  hashSha256: string;
  hashMd5: string;
  description: string;
  entropy: number; // 0.0 to 8.0
  sourceHost: string;
  collectedAt: string;
  hexPreview: string;
  extractedStrings: string[];
  decompiledCode?: string;
  behavioralTraces: Array<{
    category: 'FILE_SYSTEM' | 'PROCESS_EXEC' | 'NETWORK' | 'REGISTRY';
    action: string;
    target: string;
    risk: 'HIGH' | 'MEDIUM' | 'LOW';
  }>;
  iocs: IOCItem[];
  yaraMatches: string[];
  aiForensicReport?: {
    overview: string;
    capabilities: string[];
    packerDetected: string;
    c2Infrastructure: string[];
    antiAnalysisTechniques: string[];
    forensicConclusion: string;
  };
}

export interface DetectionRule {
  id: string;
  name: string;
  format: RuleFormat;
  severity: ThreatSeverity;
  mitreTechnique: string;
  author: string;
  createdAt: string;
  ruleContent: string;
  description: string;
  testedMatchCount: number;
}

export interface MitreTechnique {
  id: string;
  tactic: string;
  name: string;
  description: string;
  activeDetections: number;
  incidentCount: number;
  riskScore: number;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  suggestedActions?: Array<{ label: string; actionType: string; payload?: any }>;
}
