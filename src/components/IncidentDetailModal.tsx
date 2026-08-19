import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  Sparkles, 
  Terminal, 
  Clock, 
  Server, 
  User, 
  MapPin, 
  FileCode, 
  CheckCircle2, 
  Play, 
  Copy, 
  ExternalLink,
  Cpu,
  Layers,
  AlertTriangle,
  Flame,
  ArrowRight
} from 'lucide-react';
import { SecurityIncident } from '../types';
import { investigateIncidentWithAI } from '../services/api';

interface IncidentDetailModalProps {
  incident: SecurityIncident | null;
  onClose: () => void;
  onUpdateIncident: (updated: SecurityIncident) => void;
  onTriggerPlaybook: (playbookId: string, incident: SecurityIncident) => void;
  onOpenForensics: (targetHost: string) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onUpdateIncident,
  onTriggerPlaybook,
  onOpenForensics,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'ai-investigation' | 'telemetry' | 'timeline' | 'iocs' | 'remediation'>('overview');
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  if (!incident) return null;

  const handleRunAIInvestigation = async () => {
    try {
      setIsInvestigating(true);
      const res = await investigateIncidentWithAI(incident);
      if (res.success && res.analysis) {
        const updated: SecurityIncident = {
          ...incident,
          status: incident.status === 'OPEN' ? 'INVESTIGATING' : incident.status,
          aiAnalysis: res.analysis,
        };
        onUpdateIncident(updated);
        setActiveTab('ai-investigation');
      }
    } catch (err) {
      console.error('Investigation error:', err);
    } finally {
      setIsInvestigating(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2.5 py-0.5 rounded-sm bg-[#ff3e3e] text-black font-black text-[10px] tracking-wider uppercase">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2.5 py-0.5 rounded-sm bg-amber-500 text-black font-black text-[10px] tracking-wider uppercase">HIGH</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-sm bg-blue-500 text-black font-black text-[10px] tracking-wider uppercase">{sev}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 overflow-y-auto font-mono">
      <div className="bg-[#0a0a0c] border border-[#222226] rounded-sm w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 bg-[#050505] border-b border-[#222226] flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-sm bg-[#ff3e3e]/10 border border-[#ff3e3e]/30 text-[#ff3e3e] mt-1">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className="text-[#ff3e3e] text-xs font-black px-2 py-0.5 rounded-sm bg-[#ff3e3e]/10 border border-[#ff3e3e]/30">
                  {incident.id}
                </span>
                {getSeverityBadge(incident.severity)}
                <span className="px-2 py-0.5 rounded-sm text-[10px] font-bold bg-[#18181b] text-zinc-300 border border-[#333]">
                  STATUS: {incident.status}
                </span>
                <span className="text-[11px] text-zinc-400">
                  ANOMALY: <strong className="text-[#ff3e3e] font-black">{incident.anomalyScore}/100</strong>
                </span>
              </div>
              <h2 className="text-lg font-black text-white mt-1.5 uppercase tracking-wide">{incident.title}</h2>
              <p className="text-xs text-zinc-400 mt-0.5 font-sans leading-relaxed">{incident.description}</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-zinc-400 hover:text-white rounded-sm hover:bg-[#18181b] border border-transparent hover:border-[#333] transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Nav Tabs & Quick Actions */}
        <div className="px-6 py-2 bg-[#08080a] border-b border-[#222226] flex items-center justify-between gap-2 overflow-x-auto text-xs uppercase tracking-wider">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                activeTab === 'overview' ? 'bg-[#ff3e3e] text-black shadow' : 'text-zinc-400 hover:text-white'
              }`}
            >
              Overview & Assets
            </button>
            <button
              onClick={() => setActiveTab('ai-investigation')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                activeTab === 'ai-investigation'
                  ? 'bg-blue-600 text-white shadow'
                  : 'text-zinc-400 hover:text-blue-400'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>AI DFIR Investigation</span>
              {incident.aiAnalysis && <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>}
            </button>
            <button
              onClick={() => setActiveTab('telemetry')}
              className={`px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                activeTab === 'telemetry' ? 'bg-[#ff3e3e] text-black shadow' : 'text-zinc-400 hover:text-white'
              }`}
            >
              Raw Logs ({incident.rawLogs.length})
            </button>
            <button
              onClick={() => setActiveTab('timeline')}
              className={`px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                activeTab === 'timeline' ? 'bg-[#ff3e3e] text-black shadow' : 'text-zinc-400 hover:text-white'
              }`}
            >
              Attack Timeline ({incident.timelineEvents.length})
            </button>
            <button
              onClick={() => setActiveTab('iocs')}
              className={`px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                activeTab === 'iocs' ? 'bg-[#ff3e3e] text-black shadow' : 'text-zinc-400 hover:text-white'
              }`}
            >
              IOC Indicators ({incident.iocs.length})
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleRunAIInvestigation}
              disabled={isInvestigating}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-blue-600 hover:bg-blue-500 text-white text-xs font-black uppercase tracking-wider shadow transition disabled:opacity-50"
            >
              <Sparkles className={`w-3.5 h-3.5 ${isInvestigating ? 'animate-spin' : ''}`} />
              <span>{isInvestigating ? 'Analyzing...' : incident.aiAnalysis ? 'Re-Run AI' : 'Run AI Analysis'}</span>
            </button>
          </div>
        </div>

        {/* Modal Body Content */}
        <div className="p-6 overflow-y-auto flex-1 text-zinc-200 text-sm space-y-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Key Metadata Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm">
                  <div className="flex items-center gap-2 text-zinc-400 text-[10px] mb-1 font-bold uppercase tracking-wider">
                    <Server className="w-3.5 h-3.5 text-blue-400" />
                    <span>Target Endpoint</span>
                  </div>
                  <div className="font-mono font-bold text-white text-sm">{incident.targetHost}</div>
                  <div className="text-[10px] text-zinc-500 mt-1 uppercase">User: {incident.targetUser}</div>
                </div>

                <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm">
                  <div className="flex items-center gap-2 text-zinc-400 text-[10px] mb-1 font-bold uppercase tracking-wider">
                    <MapPin className="w-3.5 h-3.5 text-[#ff3e3e]" />
                    <span>Adversary Origin</span>
                  </div>
                  <div className="font-mono font-bold text-[#ff3e3e] text-sm">{incident.sourceIp}</div>
                  <div className="text-[10px] text-zinc-400 mt-1 flex items-center gap-1">
                    <span>{incident.sourceGeo.flag}</span>
                    <span>{incident.sourceGeo.city}, {incident.sourceGeo.country}</span>
                  </div>
                </div>

                <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm">
                  <div className="flex items-center gap-2 text-zinc-400 text-[10px] mb-1 font-bold uppercase tracking-wider">
                    <Layers className="w-3.5 h-3.5 text-amber-400" />
                    <span>MITRE ATT&CK</span>
                  </div>
                  <div className="font-bold text-amber-300 text-xs truncate">{incident.mitreTechnique}</div>
                  <div className="text-[10px] text-zinc-400 mt-1 uppercase">Tactic: {incident.mitreTactic}</div>
                </div>

                <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm">
                  <div className="flex items-center gap-2 text-zinc-400 text-[10px] mb-1 font-bold uppercase tracking-wider">
                    <Clock className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Detected Time</span>
                  </div>
                  <div className="font-mono font-bold text-zinc-200 text-xs">{new Date(incident.timestamp).toLocaleString()}</div>
                  <div className="text-[10px] text-emerald-400 mt-1 uppercase font-bold">Confidence: {incident.confidenceScore}%</div>
                </div>
              </div>

              {/* Blast Radius & Affected Assets */}
              <div className="p-4 bg-[#050505] border border-[#222226] rounded-sm space-y-3">
                <h4 className="text-xs font-black text-white uppercase tracking-wider flex items-center gap-2">
                  <Flame className="w-4 h-4 text-[#ff3e3e]" />
                  <span>Impacted Perimeter & Assets at Risk</span>
                </h4>
                <div className="flex flex-wrap gap-2">
                  {incident.affectedAssets.map((asset, i) => (
                    <span
                      key={i}
                      className="px-3 py-1 bg-[#150a0b] border border-[#ff3e3e]/30 rounded-sm text-xs font-mono text-zinc-200 flex items-center gap-2"
                    >
                      <Server className="w-3.5 h-3.5 text-[#ff3e3e]" />
                      <span>{asset}</span>
                      <span className="text-[10px] px-1 bg-[#ff3e3e] text-black font-black uppercase">EXPOSED</span>
                    </span>
                  ))}
                </div>
              </div>

              {/* Quick SOAR Containment Triggers */}
              <div className="p-4 bg-[#08080a] border border-[#222226] rounded-sm space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-black text-amber-400 uppercase tracking-wider flex items-center gap-2">
                    <Play className="w-4 h-4 text-amber-400" />
                    <span>Recommended Automated SOAR Containment Playbooks</span>
                  </h4>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <button
                    onClick={() => onTriggerPlaybook('pb-isolate-host', incident)}
                    className="p-3 bg-[#050505] hover:bg-[#120a0b] border border-[#222226] hover:border-[#ff3e3e] rounded-sm text-left transition group"
                  >
                    <div className="font-bold text-xs text-[#ff3e3e] flex items-center justify-between uppercase tracking-wider">
                      <span>Quarantine Host</span>
                      <ArrowRight className="w-3.5 h-3.5 text-[#ff3e3e]" />
                    </div>
                    <p className="text-[10px] text-zinc-400 mt-1 font-sans">Isolate {incident.targetHost} from internal network.</p>
                  </button>

                  <button
                    onClick={() => onTriggerPlaybook('pb-revoke-creds', incident)}
                    className="p-3 bg-[#050505] hover:bg-[#15120a] border border-[#222226] hover:border-amber-500 rounded-sm text-left transition group"
                  >
                    <div className="font-bold text-xs text-amber-400 flex items-center justify-between uppercase tracking-wider">
                      <span>Revoke Tokens</span>
                      <ArrowRight className="w-3.5 h-3.5 text-amber-400" />
                    </div>
                    <p className="text-[10px] text-zinc-400 mt-1 font-sans">Invalidate TGT & OAuth sessions for {incident.targetUser}.</p>
                  </button>

                  <button
                    onClick={() => onTriggerPlaybook('pb-block-firewall-ip', incident)}
                    className="p-3 bg-[#050505] hover:bg-[#0a1018] border border-[#222226] hover:border-blue-500 rounded-sm text-left transition group"
                  >
                    <div className="font-bold text-xs text-blue-400 flex items-center justify-between uppercase tracking-wider">
                      <span>Block C2 IP</span>
                      <ArrowRight className="w-3.5 h-3.5 text-blue-400" />
                    </div>
                    <p className="text-[10px] text-zinc-400 mt-1 font-sans">Push firewall drop rule for {incident.sourceIp}.</p>
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'ai-investigation' && (
            <div className="space-y-5">
              {!incident.aiAnalysis ? (
                <div className="p-8 text-center bg-[#050505] border border-[#222226] rounded-sm space-y-4">
                  <div className="w-12 h-12 rounded-sm bg-blue-950 border border-blue-700 text-blue-400 mx-auto flex items-center justify-center">
                    <Sparkles className="w-6 h-6 animate-pulse" />
                  </div>
                  <h3 className="text-base font-black text-white uppercase tracking-wider">No Deep AI Investigation Cached</h3>
                  <p className="text-xs text-zinc-400 max-w-md mx-auto font-sans leading-relaxed">
                    Initiate deep forensic analysis via Gemini to extract IOCs, assess root causes, profile threat actors, and synthesize containment scripts.
                  </p>
                  <button
                    onClick={handleRunAIInvestigation}
                    disabled={isInvestigating}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-sm text-xs font-black uppercase tracking-wider shadow transition"
                  >
                    {isInvestigating ? 'Analyzing Telemetry...' : 'Launch Gemini DFIR Investigation'}
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* AI Summary Banner */}
                  <div className="p-4 bg-[#080d1a] border border-blue-900/60 rounded-sm space-y-2">
                    <div className="flex items-center gap-2 text-blue-400 font-bold text-xs uppercase tracking-wider">
                      <Sparkles className="w-4 h-4 text-blue-400" />
                      <span>Executive Root-Cause Forensic Summary</span>
                    </div>
                    <p className="text-xs text-zinc-200 leading-relaxed font-sans">{incident.aiAnalysis.technicalSummary}</p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-[#050505] border border-[#222226] rounded-sm space-y-2">
                      <h4 className="text-xs font-bold text-[#ff3e3e] uppercase tracking-wider">Intrusion Vector & Root Cause</h4>
                      <p className="text-xs text-zinc-300 leading-relaxed font-sans">{incident.aiAnalysis.rootCause}</p>
                    </div>

                    <div className="p-4 bg-[#050505] border border-[#222226] rounded-sm space-y-2">
                      <h4 className="text-xs font-bold text-amber-400 uppercase tracking-wider">Threat Actor Attribution</h4>
                      <p className="text-xs text-zinc-300 leading-relaxed font-sans">{incident.aiAnalysis.threatActorProfile}</p>
                    </div>
                  </div>

                  {/* Containment Checklist */}
                  <div className="p-4 bg-[#050505] border border-[#222226] rounded-sm space-y-3">
                    <h4 className="text-xs font-bold text-white uppercase tracking-wider">Recommended DFIR Containment Checklist</h4>
                    <div className="space-y-2">
                      {incident.aiAnalysis.containmentSteps.map((step, idx) => (
                        <div key={idx} className="flex items-start gap-2 text-xs text-zinc-200">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                          <span className="font-sans">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Remediation Script */}
                  {incident.aiAnalysis.remediationScript && (
                    <div className="p-4 bg-[#050505] border border-[#222226] rounded-sm space-y-2 font-mono text-xs">
                      <div className="flex items-center justify-between text-zinc-400">
                        <span className="flex items-center gap-1.5 text-blue-400 font-bold uppercase tracking-wider">
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Automated Containment Script</span>
                        </span>
                        <button
                          onClick={() => copyToClipboard(incident.aiAnalysis?.remediationScript || '')}
                          className="flex items-center gap-1 px-2 py-1 bg-[#18181b] hover:bg-[#27272a] text-zinc-200 rounded-sm text-[10px] uppercase font-bold transition"
                        >
                          <Copy className="w-3 h-3" />
                          <span>{copiedCode ? 'Copied!' : 'Copy Script'}</span>
                        </button>
                      </div>
                      <pre className="p-3 bg-[#000] border border-[#222226] rounded-sm text-emerald-400 overflow-x-auto text-[11px] leading-relaxed">
                        {incident.aiAnalysis.remediationScript}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'telemetry' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between text-zinc-400 text-xs uppercase tracking-wider">
                <span>Ingested Telemetry Stream ({incident.rawLogs.length} Events)</span>
                <span className="text-zinc-500">Source: SIEM Real-Time Ingress</span>
              </div>
              <div className="bg-[#050505] border border-[#222226] rounded-sm p-4 space-y-2 overflow-x-auto">
                {incident.rawLogs.map((log, i) => (
                  <div key={i} className="p-2 bg-[#08080a] border border-[#1f1f23] rounded-sm text-zinc-300 text-[11px] leading-relaxed">
                    <span className="text-[#ff3e3e] font-bold mr-2">[{i + 1}]</span>
                    {log}
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="space-y-4">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider">Attack Progression Sequence</h4>
              <div className="relative pl-6 border-l-2 border-[#222226] space-y-6">
                {incident.timelineEvents.map((ev, i) => (
                  <div key={ev.id || i} className="relative group">
                    <span className={`absolute -left-[31px] top-1 w-4 h-4 rounded-sm border-2 border-black ${
                      ev.severity === 'CRITICAL' ? 'bg-[#ff3e3e]' : 'bg-amber-500'
                    }`}></span>
                    <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-white">{ev.summary}</span>
                        <span className="font-mono text-zinc-500 text-[10px]">{ev.timestamp}</span>
                      </div>
                      <div className="text-zinc-400 text-xs font-sans">{ev.details}</div>
                      <div className="flex items-center gap-2 pt-1 font-mono">
                        <span className="px-2 py-0.5 rounded-sm bg-[#18181b] text-[10px] text-blue-400 border border-[#333]">{ev.source}</span>
                        <span className="px-2 py-0.5 rounded-sm bg-[#18181b] text-[10px] text-amber-300 border border-[#333]">{ev.phase}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'iocs' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">Extracted Indicators of Compromise (IOCs)</h4>
              </div>
              <div className="border border-[#222226] rounded-sm overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#050505] text-zinc-400 uppercase text-[10px] border-b border-[#222226]">
                    <tr>
                      <th className="p-3">Type</th>
                      <th className="p-3">Indicator Value</th>
                      <th className="p-3">Reputation</th>
                      <th className="p-3">Threat Context</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#222226] bg-[#08080a]">
                    {incident.iocs.map((ioc, i) => (
                      <tr key={i} className="hover:bg-[#111113]">
                        <td className="p-3 text-blue-400 font-bold">{ioc.type}</td>
                        <td className="p-3 text-white select-all">{ioc.value}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded-sm text-[10px] font-black uppercase ${
                            ioc.reputation === 'MALICIOUS' ? 'bg-[#ff3e3e] text-black' : 'bg-amber-500 text-black'
                          }`}>
                            {ioc.reputation}
                          </span>
                        </td>
                        <td className="p-3 text-zinc-400">{ioc.sourceContext || 'Identified in memory'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 bg-[#050505] border-t border-[#222226] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-500 uppercase tracking-wider">Status:</span>
            <select
              value={incident.status}
              onChange={(e) => {
                onUpdateIncident({
                  ...incident,
                  status: e.target.value as any,
                });
              }}
              className="bg-[#0a0a0c] border border-[#333] text-xs rounded-sm px-2.5 py-1 text-zinc-200 focus:outline-none focus:border-[#ff3e3e] uppercase"
            >
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="REMEDIATED">REMEDIATED</option>
              <option value="CLOSED">CLOSED</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                onOpenForensics(incident.targetHost);
                onClose();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#18181b] hover:bg-[#27272a] text-zinc-200 text-xs font-bold uppercase tracking-wider border border-[#333] transition"
            >
              <Cpu className="w-3.5 h-3.5 text-emerald-400" />
              <span>Inspect in Forensics Lab</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-sm bg-[#ff3e3e] hover:bg-[#ff5555] text-black text-xs font-black uppercase tracking-wider shadow transition"
            >
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
