import { NormalizedSecurityEvent, SourceCategory, ThreatSeverity } from './types';
import { resolveGeoForIp } from './enrichment';

export function normalizeLog(raw: any, collectorName?: string): NormalizedSecurityEvent {
  const id = `EVT-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
  const timestamp = raw.timestamp || raw.time || raw['@timestamp'] || new Date().toISOString();

  // Determine Source Category
  let sourceType: SourceCategory = 'APPLICATION';
  if (raw.sourceType) {
    sourceType = raw.sourceType;
  } else if (raw.EventID || raw.Channel || raw.Provider_Name || raw.Computer || raw.winlog) {
    sourceType = 'WINDOWS';
  } else if (raw.facility || raw.syslog_tag || raw.audit_type || raw.ident === 'sshd' || raw.ident === 'sudo') {
    sourceType = 'LINUX';
  } else if (raw.event_type === 'alert' || raw.alert || raw.proto || raw.suricata) {
    sourceType = 'IDS_IPS';
  } else if (raw.firewall || raw.pan_threat_id || raw.action === 'DROP' || raw.rule_name) {
    sourceType = 'FIREWALL';
  } else if (raw.sensor_id || raw.falcon || raw.edr || raw.agent_id) {
    sourceType = 'EDR';
  } else if (raw.qtype || raw.qname || raw.dns_query || raw.rcode) {
    sourceType = 'DNS';
  } else if (raw.cloud || raw.userIdentity || raw.eventName) {
    sourceType = 'CLOUD';
  }

  // Extract IP addresses
  const sourceIp = raw.sourceIp || raw.src_ip || raw.srcIp || raw.client_ip || raw.c_ip || raw.SourceIp || raw.ip || '10.0.1.15';
  const destinationIp = raw.destinationIp || raw.dst_ip || raw.dstIp || raw.server_ip || raw.DestinationIp || '10.0.0.1';
  const sourcePort = raw.sourcePort || raw.src_port || raw.srcPort || undefined;
  const destinationPort = raw.destinationPort || raw.dst_port || raw.dstPort || undefined;
  const protocol = (raw.protocol || raw.proto || raw.ip_proto || 'TCP').toUpperCase();

  // Hostname and user
  const hostname = raw.hostname || raw.host || raw.Computer || raw.device_name || raw.host_name || 'WS-WORKSTATION-01';
  const user = raw.user || raw.username || raw.TargetUserName || raw.AccountName || raw.subject_user || undefined;

  // Process & command line
  const processName = raw.processName || raw.process_name || raw.Image || raw.exe || raw.app || undefined;
  const commandLine = raw.commandLine || raw.command_line || raw.CommandLine || raw.cmd || undefined;
  const parentProcessName = raw.parentProcessName || raw.parent_process || raw.ParentImage || undefined;
  const processId = raw.processId || raw.pid || raw.ProcessId || undefined;
  const eventId = raw.eventId || raw.EventID || raw.event_code || raw.event_id || undefined;

  // Hashes
  const hashes = {
    sha256: raw.sha256 || raw.SHA256 || raw.hashSha256 || (raw.Hashes && raw.Hashes.match(/SHA256=([A-Fa-f0-9]{64})/)?.[1]),
    md5: raw.md5 || raw.MD5 || (raw.Hashes && raw.Hashes.match(/MD5=([A-Fa-f0-9]{32})/)?.[1]),
  };

  // Geo
  const geo = resolveGeoForIp(sourceIp);

  // Message & Raw
  const message = raw.message || raw.msg || raw.description || raw.summary || `${sourceType} Telemetry from ${hostname} (${sourceIp} -> ${destinationIp})`;
  const rawLog = typeof raw === 'string' ? raw : JSON.stringify(raw);

  // Default Action & Status
  let action: NormalizedSecurityEvent['action'] = 'DETECT';
  if (raw.action) {
    const act = String(raw.action).toUpperCase();
    if (['ALLOW', 'BLOCK', 'DROP', 'DETECT', 'EXECUTE', 'AUTH_SUCCESS', 'AUTH_FAILURE', 'FILE_WRITE', 'DNS_QUERY'].includes(act)) {
      action = act as any;
    }
  }

  let status: NormalizedSecurityEvent['status'] = 'SUCCESS';
  if (raw.status) {
    status = raw.status;
  } else if (action === 'BLOCK' || action === 'DROP') {
    status = 'BLOCKED';
  }

  // Initial Severity & Risk Score
  let severity: ThreatSeverity = raw.severity || 'INFORMATIONAL';
  let riskScore = raw.riskScore || 10;

  return {
    id,
    timestamp,
    sourceType,
    sourceCollector: collectorName || raw.collectorName || `${sourceType}_LOG_INGRESS`,
    sourceIp,
    destinationIp,
    sourcePort: sourcePort ? Number(sourcePort) : undefined,
    destinationPort: destinationPort ? Number(destinationPort) : undefined,
    protocol,
    hostname,
    user,
    processName,
    processId: processId ? Number(processId) : undefined,
    parentProcessName,
    commandLine,
    eventId,
    action,
    status,
    message,
    rawLog,
    hashes,
    geo,
    severity,
    riskScore,
    isDemo: !!raw.isDemo,
  };
}
