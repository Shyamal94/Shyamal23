import { NormalizedSecurityEvent, SecurityAlert, SecurityIncident, ThreatSeverity, IOCItem } from './types';
import { enrichIOC } from './enrichment';

export interface DetectionResult {
  matched: boolean;
  alert?: SecurityAlert;
  incident?: SecurityIncident;
  updatedEvent: NormalizedSecurityEvent;
}

export async function evaluateEventDetections(event: NormalizedSecurityEvent): Promise<DetectionResult> {
  const updatedEvent = { ...event };
  const cmd = (event.commandLine || '').toLowerCase();
  const msg = (event.message || '').toLowerCase();
  const proc = (event.processName || '').toLowerCase();
  const raw = (event.rawLog || '').toLowerCase();

  let matched = false;
  let severity: ThreatSeverity = 'INFORMATIONAL';
  let category: SecurityIncident['category'] = 'SUSPICIOUS_EXECUTION';
  let title = '';
  let description = '';
  let mitreTactic = 'Execution';
  let mitreTechnique = 'Command and Scripting Interpreter';
  let mitreId = 'T1059.001';
  let anomalyScore = 20;

  // Rule 1: Ransomware & Shadow Copy Deletion (T1486 / T1490)
  if (cmd.includes('vssadmin') && (cmd.includes('delete') || cmd.includes('shadows')) || cmd.includes('wbadmin delete') || cmd.includes('bcdedit /set {default} bootstatuspolicy ignoreallfailures')) {
    matched = true;
    severity = 'CRITICAL';
    category = 'RANSOMWARE';
    title = 'Ransomware Pre-Encryption Artifact: Shadow Copy Wiped via VSSAdmin';
    description = `Adversary executed command line targeting Volume Shadow Copies on host ${event.hostname} to prevent automated system restoration before data encryption.`;
    mitreTactic = 'Impact';
    mitreTechnique = 'Inhibit System Recovery: Delete Volume Shadows';
    mitreId = 'T1490';
    anomalyScore = 98;
  }
  // Rule 2: Obfuscated PowerShell / Memory Injection Stager (T1059.001 / T1055)
  else if (
    (proc.includes('powershell') || proc.includes('pwsh') || cmd.includes('powershell')) &&
    (cmd.includes('-enc') || cmd.includes('-encodedcommand') || cmd.includes('-w hidden') || cmd.includes('downloadstring') || cmd.includes('iex') || cmd.includes('invoke-expression') || cmd.includes('bypass'))
  ) {
    matched = true;
    severity = 'HIGH';
    category = 'SUSPICIOUS_EXECUTION';
    title = 'Obfuscated PowerShell Stager & In-Memory Execution';
    description = `Hidden and encoded PowerShell invocation detected on host ${event.hostname} spawning dynamic memory allocation threads.`;
    mitreTactic = 'Execution';
    mitreTechnique = 'Command and Scripting Interpreter: PowerShell';
    mitreId = 'T1059.001';
    anomalyScore = 88;
  }
  // Rule 3: Credential Dumping / LSASS / Mimikatz (T1003)
  else if (cmd.includes('mimikatz') || cmd.includes('sekurlsa') || cmd.includes('lsass') || cmd.includes('procdump') && cmd.includes('lsass') || raw.includes('lsass.exe')) {
    matched = true;
    severity = 'CRITICAL';
    category = 'CREDENTIAL_DUMPING';
    title = 'LSASS Memory Dumping / Credential Theft Attempt';
    description = `Direct memory access or injection attempt observed targeting Local Security Authority Subsystem Service (LSASS) on ${event.hostname}.`;
    mitreTactic = 'Credential Access';
    mitreTechnique = 'OS Credential Dumping: LSASS Memory';
    mitreId = 'T1003.001';
    anomalyScore = 96;
  }
  // Rule 4: Cobalt Strike / Sliver C2 Beaconing (T1071.001)
  else if (
    msg.includes('cobalt strike') ||
    msg.includes('c2 beacon') ||
    event.destinationPort === 4444 ||
    event.destinationPort === 8443 ||
    event.destinationIp === '185.220.101.42' ||
    event.destinationIp === '194.26.29.112'
  ) {
    matched = true;
    severity = 'CRITICAL';
    category = 'C2_BEACON';
    title = 'Adversary Command & Control (C2) Beaconing Pattern Detected';
    description = `Repeated outbound network telemetry with jittered intervals matching known adversary C2 stager profiles connecting to ${event.destinationIp}:${event.destinationPort || 443}.`;
    mitreTactic = 'Command and Control';
    mitreTechnique = 'Application Layer Protocol: Web Protocols';
    mitreId = 'T1071.001';
    anomalyScore = 94;
  }
  // Rule 5: DNS Tunneling & Exfiltration (T1048 / T1071.004)
  else if (
    event.sourceType === 'DNS' &&
    (msg.includes('tunneling') || msg.includes('anomalous') || (event.rawLog && event.rawLog.length > 80 && (raw.includes('.xyz') || raw.includes('c2-'))))
  ) {
    matched = true;
    severity = 'HIGH';
    category = 'EXFILTRATION';
    title = 'DNS Data Exfiltration & Protocol Tunneling Detected';
    description = `High entropy subdomains and high-volume TXT record queries detected to external nameserver indicative of covert data exfiltration.`;
    mitreTactic = 'Exfiltration';
    mitreTechnique = 'Exfiltration Over Alternative Protocol: DNS';
    mitreId = 'T1048.003';
    anomalyScore = 85;
  }
  // Rule 6: Lateral Movement / Pass-the-Hash (T1550.002 / T1021.002)
  else if (cmd.includes('psexec') || cmd.includes('wmic') && cmd.includes('process call create') || msg.includes('pass-the-hash') || (event.destinationPort === 445 && msg.includes('smb'))) {
    matched = true;
    severity = 'HIGH';
    category = 'LATERAL_MOVEMENT';
    title = 'Lateral Movement via Administrative SMB / RPC Session';
    description = `Anomalous remote execution invoked over SMB admin shares from ${event.sourceIp} to host ${event.hostname}.`;
    mitreTactic = 'Lateral Movement';
    mitreTechnique = 'Remote Services: SMB/Windows Admin Shares';
    mitreId = 'T1021.002';
    anomalyScore = 82;
  }
  // Rule 7: Web Attack / SQL Injection / Exploit Payload (T1190)
  else if (msg.includes('sql injection') || msg.includes('rce') || msg.includes('exploit') || raw.includes('union select') || raw.includes('etc/passwd') || raw.includes('jndi:ldap')) {
    matched = true;
    severity = 'HIGH';
    category = 'ZERO_DAY_EXPLOIT';
    title = 'Exploit Payload & Web Application Attack Blocked';
    description = `Inbound hostile payload matching known CVE exploit signatures intercepted from origin IP ${event.sourceIp}.`;
    mitreTactic = 'Initial Access';
    mitreTechnique = 'Exploit Public-Facing Application';
    mitreId = 'T1190';
    anomalyScore = 80;
  }

  if (matched) {
    updatedEvent.severity = severity;
    updatedEvent.riskScore = anomalyScore;
    updatedEvent.mitreTactic = mitreTactic;
    updatedEvent.mitreTechnique = mitreTechnique;
    updatedEvent.mitreId = mitreId;

    // Create Alert
    const alert: SecurityAlert = {
      id: `ALT-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: new Date().toLocaleTimeString(),
      source: event.sourceCollector,
      severity,
      eventCode: event.eventId ? String(event.eventId) : 'DET-RULE-900',
      message: `${title} - Host: ${event.hostname}`,
      sourceIp: event.sourceIp,
      destinationIp: event.destinationIp,
      processName: event.processName,
      user: event.user,
      category,
      isDemo: event.isDemo,
    };

    // Extract IOCs
    const iocs: IOCItem[] = [];
    if (event.sourceIp && event.sourceIp !== '10.0.0.1' && !event.sourceIp.startsWith('127.')) {
      const enriched = await enrichIOC('IP', event.sourceIp);
      iocs.push(enriched);
    }
    if (event.hashes?.sha256) {
      const enrichedHash = await enrichIOC('HASH_SHA256', event.hashes.sha256);
      iocs.push(enrichedHash);
    }

    // Create Incident if HIGH or CRITICAL
    let incident: SecurityIncident | undefined;
    if (severity === 'CRITICAL' || severity === 'HIGH') {
      const incidentId = `INC-${Math.floor(8800 + Math.random() * 1100)}`;
      incident = {
        id: incidentId,
        title,
        description,
        category,
        severity,
        status: 'OPEN',
        sourceIp: event.sourceIp,
        sourceGeo: event.geo || { country: 'Unknown', city: 'Unknown', lat: 20, lng: 0, flag: '🌐' },
        targetHost: event.hostname,
        targetUser: event.user || 'CORP\\LocalAdmin',
        mitreTactic,
        mitreTechnique,
        mitreId,
        timestamp: event.timestamp,
        anomalyScore,
        confidenceScore: 94,
        affectedAssets: [event.hostname, event.destinationIp].filter(Boolean),
        rawLogs: [
          `[${event.timestamp}] ${event.sourceCollector} - ${event.rawLog}`,
          `Process: ${event.processName || 'N/A'} (PID: ${event.processId || 'N/A'})`,
          `CommandLine: ${event.commandLine || 'N/A'}`,
          `Network: ${event.sourceIp}:${event.sourcePort || ''} -> ${event.destinationIp}:${event.destinationPort || ''} (${event.protocol || 'TCP'})`,
        ],
        iocs,
        timelineEvents: [
          {
            id: '1',
            timestamp: new Date().toLocaleTimeString(),
            phase: mitreTactic,
            source: event.sourceCollector,
            summary: title,
            details: description,
            severity,
          },
        ],
        remediationHistory: [],
        isDemo: event.isDemo,
      };
    }

    return {
      matched: true,
      alert,
      incident,
      updatedEvent,
    };
  }

  return {
    matched: false,
    updatedEvent,
  };
}
