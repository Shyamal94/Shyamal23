import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  Download,
  Play,
  Pause,
  RefreshCw,
  Layers,
  Terminal,
  Shield,
  Clock,
  ExternalLink,
  ChevronRight,
  Sparkles,
  ArrowUpDown,
  FileCode,
} from 'lucide-react';
import { NormalizedSecurityEvent, IOCItem } from '../types';
import { fetchEvents, enrichIOC } from '../services/api';

interface ThreatHuntProps {
  isDemoMode: boolean;
  initialQuery?: string;
}

export const ThreatHunt: React.FC<ThreatHuntProps> = ({ isDemoMode, initialQuery = '' }) => {
  const [events, setEvents] = useState<NormalizedSecurityEvent[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>(initialQuery);
  const [selectedSourceType, setSelectedSourceType] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedEvent, setSelectedEvent] = useState<NormalizedSecurityEvent | null>(null);
  const [enrichedIoc, setEnrichedIoc] = useState<IOCItem | null>(null);
  const [enriching, setEnriching] = useState<boolean>(false);

  const loadEvents = async () => {
    setLoading(true);
    try {
      const res = await fetchEvents({
        limit: 150,
        sourceType: selectedSourceType !== 'ALL' ? selectedSourceType : undefined,
        severity: selectedSeverity !== 'ALL' ? selectedSeverity : undefined,
        q: searchQuery || undefined,
        isDemo: isDemoMode,
      });
      if (res.success) {
        setEvents(res.events);
      }
    } catch (err) {
      console.error('Failed to load events for hunting:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [selectedSourceType, selectedSeverity, isDemoMode]);

  // Periodic refresh when auto-refresh enabled
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadEvents();
    }, 4000);
    return () => clearInterval(interval);
  }, [autoRefresh, selectedSourceType, selectedSeverity, searchQuery, isDemoMode]);

  const handleEnrich = async (type: string, value: string) => {
    setEnriching(true);
    setEnrichedIoc(null);
    try {
      const res = await enrichIOC(type, value);
      if (res.success) {
        setEnrichedIoc(res.ioc);
      }
    } catch (err: any) {
      alert(`Enrichment failed: ${err.message}`);
    } finally {
      setEnriching(false);
    }
  };

  const exportCSV = () => {
    const headers = ['Timestamp', 'SourceType', 'Source IP', 'Dest IP', 'Port', 'Hostname', 'User', 'Process', 'Action', 'Severity', 'Message'];
    const rows = events.map((e) => [
      e.timestamp,
      e.sourceType,
      e.sourceIp,
      e.destinationIp,
      e.destinationPort || '',
      e.hostname,
      e.user || '',
      e.processName || '',
      e.action,
      e.severity,
      `"${(e.message || '').replace(/"/g, '""')}"`,
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `sentinelx-threat-hunt-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-1.5 py-0.5 rounded-sm bg-[#ff3e3e]/20 text-[#ff3e3e] border border-[#ff3e3e]/40 text-[9px] font-mono font-bold">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-1.5 py-0.5 rounded-sm bg-amber-950/60 text-amber-400 border border-amber-800 text-[9px] font-mono font-bold">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-1.5 py-0.5 rounded-sm bg-blue-950/60 text-blue-400 border border-blue-800 text-[9px] font-mono font-bold">MEDIUM</span>;
      default:
        return <span className="px-1.5 py-0.5 rounded-sm bg-zinc-800 text-zinc-400 border border-zinc-700 text-[9px] font-mono font-bold">{sev}</span>;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="p-6 bg-[#0a0a0c] border border-[#222226] rounded-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-sm bg-[#ff3e3e]/10 text-[#ff3e3e] border border-[#ff3e3e]/30">
              <Search className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-black uppercase tracking-wider text-white">Live Threat Hunting & Telemetry Explorer</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1 max-w-3xl">
            Query normalized logs across Windows, Linux, Firewalls, EDR, IDS/IPS and DNS. Inspect real source & destination IPs, hashes, ports, and parent process trees.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-mono font-bold transition border ${
              autoRefresh
                ? 'bg-emerald-950/80 text-emerald-400 border-emerald-600/40'
                : 'bg-[#18181b] text-zinc-400 border-[#333]'
            }`}
          >
            {autoRefresh ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{autoRefresh ? 'LIVE STREAM: ON' : 'PAUSED'}</span>
          </button>

          <button
            onClick={exportCSV}
            disabled={events.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#18181b] hover:bg-[#27272a] border border-[#333] rounded-sm text-xs font-mono font-bold text-zinc-300 transition disabled:opacity-40"
          >
            <Download className="w-3.5 h-3.5" />
            <span>EXPORT CSV</span>
          </button>
        </div>
      </div>

      {/* Query Bar & Filters */}
      <div className="p-4 bg-[#0a0a0c] border border-[#222226] rounded-sm space-y-3 font-mono">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            loadEvents();
          }}
          className="flex gap-2"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Hunt: 185.220... OR powershell.exe OR sha256:e3b0... OR host:DC01 OR user:Admin"
              className="w-full bg-black border border-[#27272a] rounded-sm pl-9 pr-3 py-2 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-[#ff3e3e] transition"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-[#ff3e3e] hover:bg-[#ff5555] text-black font-black text-xs uppercase tracking-wider rounded-sm transition flex items-center gap-1.5"
          >
            <Search className="w-3.5 h-3.5" />
            <span>HUNT</span>
          </button>
        </form>

        <div className="flex items-center gap-4 text-xs text-zinc-400 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase font-bold tracking-wider">Source Type:</span>
            <select
              value={selectedSourceType}
              onChange={(e) => setSelectedSourceType(e.target.value)}
              className="bg-black border border-[#27272a] rounded-sm px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:border-[#ff3e3e]"
            >
              <option value="ALL">ALL SOURCES</option>
              <option value="WINDOWS">WINDOWS</option>
              <option value="LINUX">LINUX</option>
              <option value="FIREWALL">FIREWALL</option>
              <option value="IDS_IPS">IDS/IPS</option>
              <option value="EDR">EDR</option>
              <option value="DNS">DNS</option>
              <option value="APPLICATION">APPLICATION</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase font-bold tracking-wider">Severity:</span>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-black border border-[#27272a] rounded-sm px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:border-[#ff3e3e]"
            >
              <option value="ALL">ALL SEVERITIES</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFORMATIONAL">INFORMATIONAL</option>
            </select>
          </div>

          <span className="text-zinc-600">|</span>

          <span className="text-xs">
            Showing <strong className="text-white">{events.length}</strong> matching records
          </span>
        </div>
      </div>

      {/* Main Results Table */}
      <div className="bg-[#0a0a0c] border border-[#222226] rounded-sm overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-[#050505] border-b border-[#222226] text-[10px] text-zinc-400 uppercase tracking-widest">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Source Type</th>
                <th className="p-3">Source IP & Port</th>
                <th className="p-3">Dest IP & Port</th>
                <th className="p-3">Host / User</th>
                <th className="p-3">Process / Action</th>
                <th className="p-3">Message & Telemetry Summary</th>
                <th className="p-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#18181b]">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-zinc-500 font-mono">
                    <p className="text-sm font-bold text-zinc-400">No events matched query</p>
                    <p className="text-xs mt-1">
                      {isDemoMode
                        ? 'Try clearing the search filter or switching severity.'
                        : 'No live events ingested yet. Send logs to POST /api/events or trigger test collectors in Data Sources.'}
                    </p>
                  </td>
                </tr>
              ) : (
                events.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-[#121216] transition cursor-pointer group"
                  >
                    <td className="p-3 text-zinc-400 whitespace-nowrap text-[11px]">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="p-3 whitespace-nowrap">{getSeverityBadge(evt.severity)}</td>
                    <td className="p-3 whitespace-nowrap">
                      <span className="px-1.5 py-0.5 rounded-sm bg-[#18181b] border border-[#27272a] text-zinc-300 font-bold text-[10px]">
                        {evt.sourceType}
                      </span>
                    </td>
                    <td className="p-3 whitespace-nowrap text-rose-300 font-bold">
                      {evt.sourceIp}
                      {evt.sourcePort ? `:${evt.sourcePort}` : ''}
                    </td>
                    <td className="p-3 whitespace-nowrap text-zinc-300">
                      {evt.destinationIp}
                      {evt.destinationPort ? `:${evt.destinationPort}` : ''}
                    </td>
                    <td className="p-3 whitespace-nowrap text-zinc-300">
                      <div className="font-bold text-white">{evt.hostname}</div>
                      <div className="text-[10px] text-zinc-500">{evt.user || 'SYSTEM'}</div>
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <div className="text-zinc-200 font-bold truncate max-w-[140px]">{evt.processName || evt.action}</div>
                      <div className="text-[10px] text-zinc-500">{evt.protocol || 'TCP'}</div>
                    </td>
                    <td className="p-3 text-zinc-300 max-w-xs truncate text-[11px]">{evt.message}</td>
                    <td className="p-3 text-right">
                      <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-white transition inline" />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-over / Modal Detail Inspector */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-end p-0 sm:p-4">
          <div className="w-full max-w-2xl h-full bg-[#0a0a0c] border border-[#222226] shadow-2xl flex flex-col justify-between font-mono">
            {/* Header */}
            <div className="p-5 border-b border-[#222226] flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-zinc-400 uppercase tracking-widest">Event Inspector</span>
                  {getSeverityBadge(selectedEvent.severity)}
                </div>
                <h3 className="text-base font-black text-white mt-1">{selectedEvent.message}</h3>
              </div>
              <button
                onClick={() => {
                  setSelectedEvent(null);
                  setEnrichedIoc(null);
                }}
                className="p-1.5 text-zinc-400 hover:text-white border border-[#333] rounded-sm text-xs"
              >
                ✕
              </button>
            </div>

            {/* Body */}
            <div className="p-5 space-y-5 overflow-y-auto flex-1 text-xs">
              {/* Event Attributes Grid */}
              <div className="grid grid-cols-2 gap-3 bg-black p-4 border border-[#222226] rounded-sm">
                <div>
                  <span className="text-[10px] text-zinc-500 uppercase block">Source IP (Attacker)</span>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-rose-400 font-bold">{selectedEvent.sourceIp}</span>
                    <button
                      onClick={() => handleEnrich('IP', selectedEvent.sourceIp)}
                      className="px-1.5 py-0.5 bg-[#18181b] hover:bg-[#27272a] border border-[#333] rounded-sm text-[9px] text-blue-400 font-bold"
                    >
                      Enrich TI
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-zinc-500 uppercase block">Destination IP</span>
                  <span className="text-zinc-300 font-bold mt-0.5 block">{selectedEvent.destinationIp}:{selectedEvent.destinationPort || 'ANY'}</span>
                </div>

                <div>
                  <span className="text-[10px] text-zinc-500 uppercase block">Hostname & User</span>
                  <span className="text-white font-bold mt-0.5 block">{selectedEvent.hostname} ({selectedEvent.user || 'N/A'})</span>
                </div>

                <div>
                  <span className="text-[10px] text-zinc-500 uppercase block">Process & PID</span>
                  <span className="text-emerald-400 font-bold mt-0.5 block">{selectedEvent.processName || 'N/A'} (PID: {selectedEvent.processId || 'N/A'})</span>
                </div>

                {selectedEvent.mitreTechnique && (
                  <div className="col-span-2">
                    <span className="text-[10px] text-zinc-500 uppercase block">MITRE ATT&CK Mapping</span>
                    <span className="text-purple-400 font-bold mt-0.5 block">
                      {selectedEvent.mitreTactic} &gt; {selectedEvent.mitreTechnique} ({selectedEvent.mitreId})
                    </span>
                  </div>
                )}
              </div>

              {/* Enrichment Display */}
              {enriching && <div className="p-3 bg-blue-950/40 border border-blue-800 text-blue-300 text-xs">Querying Threat Intelligence Vault...</div>}
              {enrichedIoc && (
                <div className="p-4 bg-[#121218] border border-blue-600/40 rounded-sm space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-blue-400 font-bold">
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Threat Intelligence Profile: {enrichedIoc.value}</span>
                    </div>
                    <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded-sm ${
                      enrichedIoc.reputation === 'MALICIOUS' ? 'bg-[#ff3e3e] text-black' : 'bg-amber-500 text-black'
                    }`}>
                      {enrichedIoc.reputation}
                    </span>
                  </div>
                  <p className="text-zinc-300 text-[11px]">{enrichedIoc.sourceContext}</p>
                  {enrichedIoc.geo && (
                    <div className="text-[10px] text-zinc-400">
                      Location: {enrichedIoc.geo.flag} {enrichedIoc.geo.city}, {enrichedIoc.geo.country}
                    </div>
                  )}
                </div>
              )}

              {/* Command Line */}
              {selectedEvent.commandLine && (
                <div>
                  <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block mb-1">
                    Process Command Line
                  </span>
                  <pre className="p-3 bg-black border border-[#222226] rounded-sm text-amber-300 whitespace-pre-wrap break-all text-[11px]">
                    {selectedEvent.commandLine}
                  </pre>
                </div>
              )}

              {/* Raw Log */}
              <div>
                <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block mb-1">
                  Raw Collector Telemetry
                </span>
                <pre className="p-3 bg-black border border-[#222226] rounded-sm text-zinc-400 whitespace-pre-wrap break-all text-[10px] leading-relaxed">
                  {selectedEvent.rawLog}
                </pre>
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-[#222226] bg-[#050505] flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 bg-[#18181b] hover:bg-[#27272a] border border-[#333] text-white text-xs font-bold uppercase rounded-sm"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
