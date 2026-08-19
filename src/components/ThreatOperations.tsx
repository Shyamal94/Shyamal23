import React, { useState } from 'react';
import {
  ShieldAlert,
  Activity,
  Radio,
  Filter,
  ArrowUpRight,
  Play,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Clock,
  Sparkles,
  Server,
  Zap,
  TrendingUp,
  Search,
  RefreshCw,
  Cpu,
  PlusCircle,
} from 'lucide-react';
import { SecurityIncident, SecurityAlert } from '../types';
import { GeoThreatVisualizer } from './GeoThreatVisualizer';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface ThreatOperationsProps {
  incidents: SecurityIncident[];
  alertsFeed: SecurityAlert[];
  onSelectIncident: (inc: SecurityIncident) => void;
  onQuickContain: (inc: SecurityIncident) => void;
  onSimulateThreat: (scenario: string) => void;
  searchQuery: string;
  isDemoMode: boolean;
  onOpenDataSources: () => void;
  onIngestSample: () => void;
}

export const ThreatOperations: React.FC<ThreatOperationsProps> = ({
  incidents,
  alertsFeed,
  onSelectIncident,
  onQuickContain,
  onSimulateThreat,
  searchQuery,
  isDemoMode,
  onOpenDataSources,
  onIngestSample,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);

  // Filtered incidents
  const filteredIncidents = incidents.filter((inc) => {
    if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && inc.category !== categoryFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchText = `${inc.id} ${inc.title} ${inc.description} ${inc.sourceIp} ${inc.targetHost} ${inc.mitreTechnique} ${inc.mitreId}`.toLowerCase();
      return matchText.includes(q);
    }
    return true;
  });

  const criticalCount = incidents.filter((i) => i.severity === 'CRITICAL').length;
  const highCount = incidents.filter((i) => i.severity === 'HIGH').length;
  const openCount = incidents.filter((i) => i.status === 'OPEN' || i.status === 'INVESTIGATING').length;

  const chartData = [
    { time: '10:00', eps: isDemoMode ? 12400 : 24, anomalies: isDemoMode ? 3 : 0, blockedAttacks: isDemoMode ? 18 : 0 },
    { time: '10:02', eps: isDemoMode ? 13100 : 38, anomalies: isDemoMode ? 5 : 1, blockedAttacks: isDemoMode ? 22 : 1 },
    { time: '10:04', eps: isDemoMode ? 12800 : 45, anomalies: isDemoMode ? 4 : 0, blockedAttacks: isDemoMode ? 19 : 0 },
    { time: '10:06', eps: isDemoMode ? 14200 : 62, anomalies: isDemoMode ? 12 : 2, blockedAttacks: isDemoMode ? 45 : 2 },
    { time: '10:08', eps: isDemoMode ? 18900 : 88, anomalies: isDemoMode ? 28 : 4, blockedAttacks: isDemoMode ? 89 : 3 },
    { time: '10:10', eps: isDemoMode ? 15400 : 54, anomalies: isDemoMode ? 16 : 1, blockedAttacks: isDemoMode ? 62 : 1 },
    { time: '10:12', eps: isDemoMode ? 14892 : 72, anomalies: isDemoMode ? 9 : 2, blockedAttacks: isDemoMode ? 36 : 2 },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Demo Mode Notice Banner */}
      {isDemoMode && (
        <div className="p-3 bg-amber-950/40 border border-amber-600/50 rounded-sm flex items-center justify-between font-mono text-xs text-amber-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span>
              <strong>[DEMO SIMULATION ACTIVE]:</strong> Showing synthetic training scenarios and pre-configured forensic artifacts. Switch to <strong>LIVE MODE</strong> to ingest real corporate telemetry.
            </span>
          </div>
          <button
            onClick={onIngestSample}
            className="px-3 py-1 bg-amber-500 hover:bg-amber-400 text-black font-black uppercase text-[10px] rounded-sm transition whitespace-nowrap"
          >
            Inject Sample Ingestion
          </button>
        </div>
      )}

      {/* Top Metrics Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 font-mono">
        <div className="p-4 bg-[#0a0a0c] border border-[#222226] rounded-sm shadow-md relative overflow-hidden">
          <div className="absolute right-3 top-3 text-[#ff3e3e]/10">
            <ShieldAlert className="w-12 h-12" />
          </div>
          <div className="text-[10px] font-bold text-zinc-400 uppercase tracking-[0.2em]">Critical Threats</div>
          <div className="text-3xl sm:text-4xl font-black text-[#ff3e3e] mt-1 tracking-tight">{criticalCount}</div>
          <div className="text-[10px] text-[#ff3e3e]/90 mt-2 flex items-center gap-1.5 font-bold uppercase tracking-wider">
            <span className="w-1.5 h-1.5 rounded-full bg-[#ff3e3e] animate-ping"></span>
            <span>Immediate Triage</span>
          </div>
        </div>

        <div className="p-4 bg-[#0a0a0c] border border-[#222226] rounded-sm shadow-md relative overflow-hidden">
          <div className="absolute right-3 top-3 text-amber-500/10">
            <AlertTriangle className="w-12 h-12" />
          </div>
          <div className="text-[10px] font-bold text-zinc-400 uppercase tracking-[0.2em]">Active Investigations</div>
          <div className="text-3xl sm:text-4xl font-black text-amber-400 mt-1 tracking-tight">{openCount}</div>
          <div className="text-[10px] text-zinc-400 mt-2 uppercase tracking-wider">
            Across <strong className="text-white">{incidents.length}</strong> incidents
          </div>
        </div>

        <div className="p-4 bg-[#0a0a0c] border border-[#222226] rounded-sm shadow-md relative overflow-hidden">
          <div className="absolute right-3 top-3 text-blue-500/10">
            <Activity className="w-12 h-12" />
          </div>
          <div className="text-[10px] font-bold text-zinc-400 uppercase tracking-[0.2em]">Ingress Rate</div>
          <div className="text-3xl sm:text-4xl font-black text-blue-400 mt-1 tracking-tight">
            {isDemoMode ? '14,892' : alertsFeed.length > 0 ? '72' : '0'}{' '}
            <span className="text-xs font-normal text-zinc-400">EPS</span>
          </div>
          <div className="text-[10px] text-blue-400 mt-2 flex items-center gap-1 uppercase tracking-wider font-bold">
            <TrendingUp className="w-3 h-3" />
            <span>{isDemoMode ? '+18.4% Ingress Surge' : 'Real Ingest Stream'}</span>
          </div>
        </div>

        <div className="p-4 bg-[#0a0a0c] border border-[#222226] rounded-sm shadow-md relative overflow-hidden">
          <div className="absolute right-3 top-3 text-emerald-500/10">
            <Zap className="w-12 h-12" />
          </div>
          <div className="text-[10px] font-bold text-zinc-400 uppercase tracking-[0.2em]">Autonomous Blocks</div>
          <div className="text-3xl sm:text-4xl font-black text-emerald-400 mt-1 tracking-tight">
            {isDemoMode ? '173' : '12'}
          </div>
          <div className="text-[10px] text-zinc-400 mt-2 uppercase tracking-wider">
            Latency: <strong className="text-emerald-400">1.8s</strong> Avg
          </div>
        </div>
      </div>

      {/* Real-time Telemetry Graph & Threat Origin Map */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Real-time Ingestion Stream Chart */}
        <div className="lg:col-span-7 bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#ff3e3e]" />
              <h3 className="text-sm font-black uppercase tracking-wider text-white">SIEM Telemetry & Anomaly Spikes</h3>
            </div>
            <span className="text-[10px] text-zinc-400 font-mono uppercase tracking-widest">Rolling Window</span>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="epsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="anomalyGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff3e3e" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#ff3e3e" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#52525b" fontSize={10} fontFamily="JetBrains Mono" />
                <YAxis stroke="#52525b" fontSize={10} fontFamily="JetBrains Mono" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#09090b',
                    borderColor: '#27272a',
                    borderRadius: '2px',
                    fontSize: '11px',
                    fontFamily: 'JetBrains Mono',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="eps"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#epsGrad)"
                  name="Events Ingestion (EPS)"
                />
                <Area
                  type="monotone"
                  dataKey="anomalies"
                  stroke="#ff3e3e"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#anomalyGrad)"
                  name="Anomalies Flagged"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-between pt-3 border-t border-[#222226] text-[10px] text-zinc-400 font-mono uppercase tracking-wider">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5 text-blue-400 font-bold">
                <span className="w-2 h-2 rounded-sm bg-blue-400 inline-block"></span>
                EPS Ingestion
              </span>
              <span className="flex items-center gap-1.5 text-[#ff3e3e] font-bold">
                <span className="w-2 h-2 rounded-sm bg-[#ff3e3e] inline-block"></span>
                Threat Anomalies
              </span>
            </div>
            <span className="text-zinc-500">Live WebSocket Feed</span>
          </div>
        </div>

        {/* Right: Geo Threat Map */}
        <div className="lg:col-span-5">
          <GeoThreatVisualizer incidents={incidents} onSelectIncident={onSelectIncident} />
        </div>
      </div>

      {/* Main Incident Queue & Live Alert Stream Section */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Active Incidents Queue (Left/Center 8 cols) */}
        <div className="xl:col-span-8 bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-lg space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-[#222226]">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-[#ff3e3e]" />
              <h3 className="text-base font-black uppercase tracking-wider text-white">Active Triage Queue</h3>
              <span className="px-2 py-0.5 rounded-sm bg-[#18181b] border border-[#333] text-[10px] text-zinc-300 font-mono font-bold">
                {filteredIncidents.length}
              </span>
            </div>

            {/* Filter controls */}
            <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#050505] border border-[#333] text-zinc-200 rounded-sm px-2.5 py-1 text-xs focus:outline-none focus:border-[#ff3e3e] uppercase tracking-wider"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical Only</option>
                <option value="HIGH">High Only</option>
              </select>

              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="bg-[#050505] border border-[#333] text-zinc-200 rounded-sm px-2.5 py-1 text-xs focus:outline-none focus:border-[#ff3e3e] uppercase tracking-wider"
              >
                <option value="ALL">All Categories</option>
                <option value="RANSOMWARE">Ransomware</option>
                <option value="LATERAL_MOVEMENT">Lateral Movement</option>
                <option value="C2_BEACON">C2 Beacon</option>
                <option value="EXFILTRATION">Exfiltration</option>
                <option value="CREDENTIAL_DUMPING">Credential Dumping</option>
              </select>
            </div>
          </div>

          {/* Incidents Card Grid */}
          <div className="space-y-3">
            {filteredIncidents.length === 0 ? (
              <div className="p-10 text-center bg-[#050505] rounded-sm border border-[#222] font-mono space-y-3">
                <div className="w-12 h-12 mx-auto rounded-full bg-[#18181b] flex items-center justify-center text-zinc-500">
                  <Server className="w-6 h-6" />
                </div>
                <div>
                  <h4 className="text-sm font-black text-white uppercase tracking-wider">
                    {isDemoMode ? 'No incidents match active filter' : 'No Live Telemetry Connected'}
                  </h4>
                  <p className="text-xs text-zinc-400 mt-1 max-w-md mx-auto">
                    {isDemoMode
                      ? 'Reset filter settings above or simulate an attack scenario.'
                      : 'SentinelX is active and listening for live logs on POST /api/events. Connect your Windows Event Collectors, Syslog agents, or firewalls.'}
                  </p>
                </div>
                {!isDemoMode && (
                  <div className="flex items-center justify-center gap-3 pt-2">
                    <button
                      onClick={onOpenDataSources}
                      className="px-4 py-2 bg-[#ff3e3e] hover:bg-[#ff5555] text-black font-black text-xs uppercase tracking-wider rounded-sm transition flex items-center gap-1.5"
                    >
                      <Server className="w-3.5 h-3.5" />
                      <span>Configure Data Sources</span>
                    </button>
                    <button
                      onClick={onIngestSample}
                      className="px-4 py-2 bg-[#18181b] hover:bg-[#27272a] border border-[#333] text-white font-bold text-xs uppercase tracking-wider rounded-sm transition"
                    >
                      Send Test Ingestion Event
                    </button>
                  </div>
                )}
              </div>
            ) : (
              filteredIncidents.map((inc) => (
                <div
                  key={inc.id}
                  className={`p-4 rounded-sm border transition group hover:border-[#ff3e3e] ${
                    inc.severity === 'CRITICAL'
                      ? 'bg-[#0f090a] border-[#ff3e3e]/30'
                      : 'bg-[#08080a] border-[#222226]'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 font-mono">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="text-[#ff3e3e] text-xs font-black px-2 py-0.5 rounded-sm bg-[#ff3e3e]/10 border border-[#ff3e3e]/30">
                        {inc.id}
                      </span>
                      {inc.isDemo && (
                        <span className="px-1.5 py-0.5 rounded-sm text-[9px] font-mono bg-amber-950/80 text-amber-300 border border-amber-600/50 font-bold uppercase tracking-wider">
                          [DEMO]
                        </span>
                      )}
                      <span
                        className={`px-2 py-0.5 rounded-sm text-[10px] font-black uppercase tracking-wider ${
                          inc.severity === 'CRITICAL' ? 'bg-[#ff3e3e] text-black' : 'bg-amber-500 text-black'
                        }`}
                      >
                        {inc.severity}
                      </span>
                      <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono bg-[#18181b] text-zinc-300 border border-[#333]">
                        {inc.status}
                      </span>
                      <span className="text-[11px] text-zinc-400">
                        Anomaly: <strong className="text-[#ff3e3e] font-black">{inc.anomalyScore}%</strong>
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => onQuickContain(inc)}
                        className="flex items-center gap-1 px-2.5 py-1 rounded-sm bg-[#1a140a] hover:bg-amber-950 text-amber-300 border border-amber-800 text-xs font-bold font-mono uppercase tracking-wider transition"
                      >
                        <Zap className="w-3 h-3" />
                        <span>Contain Host</span>
                      </button>
                      <button
                        onClick={() => onSelectIncident(inc)}
                        className="flex items-center gap-1 px-3 py-1 rounded-sm bg-[#ff3e3e] hover:bg-[#ff5555] text-black text-xs font-black uppercase tracking-wider shadow transition"
                      >
                        <span>Deep Triage</span>
                        <ArrowUpRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  <div className="mt-2.5">
                    <h4 className="font-bold text-white text-sm tracking-tight">{inc.title}</h4>
                    <p className="text-xs text-zinc-400 mt-1 leading-relaxed">{inc.description}</p>
                  </div>

                  {/* Incident Metadata Footprint */}
                  <div className="mt-3 pt-3 border-t border-[#222226] flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-400 font-mono">
                    <div className="flex items-center gap-4 flex-wrap text-[11px]">
                      <span>
                        Target: <strong className="text-white">{inc.targetHost}</strong>
                      </span>
                      <span className="text-zinc-600">•</span>
                      <span>
                        Source: <strong className="text-[#ff3e3e]">{inc.sourceIp}</strong>{' '}
                        {inc.sourceGeo && `(${inc.sourceGeo.city}, ${inc.sourceGeo.country})`}
                      </span>
                      <span className="text-zinc-600">•</span>
                      <span>
                        Tactic: <strong className="text-amber-300">{inc.mitreTechnique}</strong>
                      </span>
                    </div>
                    {inc.aiAnalysis && (
                      <span className="flex items-center gap-1 text-blue-400 font-bold text-[10px] uppercase tracking-wider">
                        <Sparkles className="w-3 h-3 text-blue-400" />
                        <span>AI Investigated</span>
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Live Security Alerts Feed (Right 4 cols) */}
        <div className="xl:col-span-4 bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-lg flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#222226]">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
              <h3 className="text-sm font-black uppercase tracking-wider text-white">Live Ingestion Stream</h3>
            </div>
            <button
              onClick={() => setIsLiveStreaming(!isLiveStreaming)}
              className="text-[10px] font-mono px-2 py-0.5 rounded-sm bg-[#18181b] border border-[#333] text-zinc-300 hover:text-white uppercase tracking-wider"
            >
              {isLiveStreaming ? 'Streaming: ON' : 'Paused'}
            </button>
          </div>

          <div className="space-y-2.5 max-h-[640px] overflow-y-auto pr-1 font-mono text-xs">
            {alertsFeed.length === 0 ? (
              <div className="p-6 text-center text-zinc-500 font-mono text-xs">
                {isDemoMode
                  ? 'No active alerts in stream.'
                  : 'Awaiting raw log stream... Send logs to POST /api/events.'}
              </div>
            ) : (
              alertsFeed.map((alt) => (
                <div
                  key={alt.id}
                  className="p-3 bg-[#08080a] border border-[#222226] rounded-sm hover:border-[#333] transition space-y-1.5"
                >
                  <div className="flex items-center justify-between text-[11px]">
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold text-white uppercase">{alt.source}</span>
                      {alt.isDemo && (
                        <span className="text-[8px] px-1 bg-amber-950 text-amber-400 border border-amber-800 rounded-sm">
                          DEMO
                        </span>
                      )}
                    </div>
                    <span className="text-zinc-500 text-[10px]">{alt.timestamp}</span>
                  </div>
                  <div className="text-zinc-300 text-xs leading-snug">{alt.message}</div>
                  <div className="flex items-center justify-between text-[10px] text-zinc-400 pt-1.5 border-t border-[#18181b]">
                    <span>Src: {alt.sourceIp}</span>
                    <span
                      className={`px-1.5 py-0.2 rounded-sm font-black uppercase ${
                        alt.severity === 'CRITICAL'
                          ? 'text-[#ff3e3e] bg-[#ff3e3e]/10 border border-[#ff3e3e]/30'
                          : 'text-amber-400 bg-amber-950/40 border border-amber-800'
                      }`}
                    >
                      {alt.severity}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="p-3 bg-[#08080a] border border-[#222226] rounded-sm text-xs font-mono space-y-2">
            <div className="font-bold text-zinc-300 flex items-center justify-between text-[11px] uppercase tracking-wider">
              <span>Sensor Health Status</span>
              <span className="text-emerald-400">100% Operational</span>
            </div>
            <div className="w-full bg-[#18181b] h-1.5 rounded-none overflow-hidden">
              <div className="bg-emerald-500 h-full w-[99.8%]"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
