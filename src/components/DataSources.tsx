import React, { useState, useEffect } from 'react';
import {
  Server,
  Radio,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Key,
  Copy,
  Check,
  Send,
  RefreshCw,
  Terminal,
  Shield,
  Activity,
  Zap,
  ArrowUpRight,
  ExternalLink,
} from 'lucide-react';
import { DataSource } from '../types';
import { fetchDataSources, testDataSource, ingestSecurityLog } from '../services/api';

interface DataSourcesProps {
  onIngestSuccess?: () => void;
}

export const DataSources: React.FC<DataSourcesProps> = ({ onIngestSuccess }) => {
  const [dataSources, setDataSources] = useState<DataSource[]>([]);
  const [activeApiKey, setActiveApiKey] = useState<string>('sx-live-secops-token-8942');
  const [loading, setLoading] = useState<boolean>(true);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [selectedSource, setSelectedSource] = useState<DataSource | null>(null);
  const [manualLogPayload, setManualLogPayload] = useState<string>(
    JSON.stringify(
      {
        sourceType: 'WINDOWS',
        hostname: 'SRV-PROD-DC01',
        sourceIp: '194.26.29.112',
        destinationIp: '10.0.1.10',
        destinationPort: 443,
        protocol: 'TCP',
        user: 'CORP\\DomainAdmin',
        processName: 'powershell.exe',
        commandLine: 'powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==',
        message: 'Suspicious Base64 PowerShell execution detected via Sysmon Event 1',
        action: 'EXECUTE',
        severity: 'HIGH',
      },
      null,
      2
    )
  );
  const [isSubmittingManual, setIsSubmittingManual] = useState<boolean>(false);
  const [manualResult, setManualResult] = useState<string | null>(null);

  const loadSources = async () => {
    setLoading(true);
    try {
      const res = await fetchDataSources();
      if (res.success) {
        setDataSources(res.dataSources);
        if (res.activeIngestKey) setActiveApiKey(res.activeIngestKey);
        if (!selectedSource && res.dataSources.length > 0) {
          setSelectedSource(res.dataSources[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load data sources:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSources();
  }, []);

  const handleTestCollector = async (sourceId: string) => {
    setTestingId(sourceId);
    try {
      const res = await testDataSource(sourceId);
      await loadSources();
      if (onIngestSuccess) onIngestSuccess();
    } catch (err: any) {
      alert(`Diagnostic test failed: ${err.message}`);
    } finally {
      setTestingId(null);
    }
  };

  const handleCopyKey = () => {
    navigator.clipboard.writeText(activeApiKey);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleSendManualEvent = async () => {
    setIsSubmittingManual(true);
    setManualResult(null);
    try {
      const parsed = JSON.parse(manualLogPayload);
      const res = await ingestSecurityLog(parsed, activeApiKey);
      setManualResult(`[✓] Success! Ingested ${res.ingestedCount} event(s), triggered ${res.alertsCount} alert(s) and ${res.incidentsCount} incident(s). Sample ID: ${res.sampleId}`);
      await loadSources();
      if (onIngestSuccess) onIngestSuccess();
    } catch (err: any) {
      setManualResult(`[!] Ingestion Error: ${err.message}`);
    } finally {
      setIsSubmittingManual(false);
    }
  };

  const getStatusBadge = (status: DataSource['status']) => {
    switch (status) {
      case 'CONNECTED':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 font-mono text-[10px] font-black uppercase tracking-wider">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
            <span>CONNECTED</span>
          </span>
        );
      case 'DISCONNECTED':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm bg-zinc-900 border border-zinc-700 text-zinc-400 font-mono text-[10px] font-bold uppercase tracking-wider">
            <span className="w-1.5 h-1.5 rounded-full bg-zinc-500"></span>
            <span>DISCONNECTED</span>
          </span>
        );
      case 'ERROR':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm bg-rose-950/80 border border-rose-600/50 text-rose-400 font-mono text-[10px] font-bold uppercase tracking-wider">
            <XCircle className="w-3 h-3 text-rose-400" />
            <span>ERROR</span>
          </span>
        );
      case 'NOT CONFIGURED':
      default:
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm bg-amber-950/60 border border-amber-600/40 text-amber-400 font-mono text-[10px] font-bold uppercase tracking-wider">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            <span>NOT CONFIGURED</span>
          </span>
        );
    }
  };

  const totalConnected = dataSources.filter((d) => d.status === 'CONNECTED').length;
  const totalEvents = dataSources.reduce((acc, d) => acc + d.eventsIngested, 0);

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="p-6 bg-[#0a0a0c] border border-[#222226] rounded-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-sm bg-[#ff3e3e]/10 text-[#ff3e3e] border border-[#ff3e3e]/30">
              <Server className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-black uppercase tracking-wider text-white">Security Data Sources & Collectors</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1 max-w-3xl">
            Live ingestion connectors for Windows Event Logs, Palo Alto Firewalls, CrowdStrike EDR, Suricata IDS, Linux Auditd, CoreDNS, and universal REST API endpoints.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadSources}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#18181b] hover:bg-[#27272a] border border-[#333] rounded-sm text-xs font-mono font-bold text-zinc-300 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>REFRESH</span>
          </button>
        </div>
      </div>

      {/* Metrics Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono">
        <div className="p-4 bg-[#0a0a0c] border border-[#222226] rounded-sm">
          <div className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Active Connectors</div>
          <div className="text-3xl font-black text-emerald-400 mt-1">
            {totalConnected} / {dataSources.length}
          </div>
          <div className="text-[10px] text-zinc-400 mt-1">Stream status healthy</div>
        </div>

        <div className="p-4 bg-[#0a0a0c] border border-[#222226] rounded-sm">
          <div className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Ingested Telemetry</div>
          <div className="text-3xl font-black text-white mt-1">{totalEvents.toLocaleString()}</div>
          <div className="text-[10px] text-zinc-400 mt-1">Normalized security events</div>
        </div>

        <div className="p-4 bg-[#0a0a0c] border border-[#222226] rounded-sm">
          <div className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Ingest Auth Token</div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs font-mono text-zinc-200 truncate bg-black px-2 py-1 border border-[#333] rounded-sm flex-1">
              {activeApiKey}
            </span>
            <button
              onClick={handleCopyKey}
              className="p-1.5 bg-[#18181b] hover:bg-[#27272a] border border-[#333] rounded-sm text-zinc-300 transition"
              title="Copy Ingest Token"
            >
              {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          <div className="text-[9px] text-zinc-400 mt-1">Authorization: Bearer &lt;TOKEN&gt;</div>
        </div>
      </div>

      {/* Main Grid: Data Source Cards + Detail/Simulator Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: List of Data Sources */}
        <div className="lg:col-span-7 space-y-3">
          <h3 className="text-xs font-black uppercase tracking-wider text-zinc-400 px-1">Configured Collectors</h3>

          {dataSources.map((ds) => {
            const isSelected = selectedSource?.id === ds.id;
            return (
              <div
                key={ds.id}
                onClick={() => setSelectedSource(ds)}
                className={`p-4 bg-[#0a0a0c] border rounded-sm transition cursor-pointer ${
                  isSelected ? 'border-[#ff3e3e] shadow-lg bg-[#0e0e12]' : 'border-[#222226] hover:border-[#3f3f46]'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-[#18181b] text-zinc-300 font-bold border border-[#333]">
                        {ds.category}
                      </span>
                      <h4 className="text-sm font-bold text-white">{ds.name}</h4>
                    </div>
                    <p className="text-xs text-zinc-400 mt-1">{ds.description}</p>
                  </div>
                  <div>{getStatusBadge(ds.status)}</div>
                </div>

                <div className="mt-3 pt-3 border-t border-[#1a1a1e] flex items-center justify-between text-xs font-mono text-zinc-400 flex-wrap gap-2">
                  <div className="flex items-center gap-4">
                    <span>
                      Events: <strong className="text-white">{ds.eventsIngested.toLocaleString()}</strong>
                    </span>
                    <span>
                      Rate: <strong className="text-blue-400">{ds.epsRate} EPS</strong>
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleTestCollector(ds.id);
                      }}
                      disabled={testingId === ds.id}
                      className="px-2 py-1 bg-[#18181b] hover:bg-[#27272a] border border-[#333] rounded-sm text-[10px] font-bold text-white uppercase tracking-wider flex items-center gap-1 transition"
                    >
                      <Zap className={`w-3 h-3 text-[#ff3e3e] ${testingId === ds.id ? 'animate-spin' : ''}`} />
                      <span>{testingId === ds.id ? 'TESTING...' : 'TEST INGEST'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Column: Selected Collector Setup Guide & Live Event Ingestion Tester */}
        <div className="lg:col-span-5 space-y-4">
          {selectedSource && (
            <div className="p-5 bg-[#0a0a0c] border border-[#222226] rounded-sm space-y-4">
              <div className="flex items-center justify-between border-b border-[#222226] pb-3">
                <div>
                  <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-widest">Collector Guide</span>
                  <h4 className="text-sm font-black text-white">{selectedSource.name}</h4>
                </div>
                {getStatusBadge(selectedSource.status)}
              </div>

              <div>
                <label className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider block mb-1">
                  Ingestion Endpoint & Method
                </label>
                <div className="p-2 bg-black border border-[#27272a] rounded-sm font-mono text-xs text-emerald-400 break-all">
                  POST {selectedSource.endpointUrl}
                </div>
              </div>

              <div>
                <label className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider block mb-1">
                  Collector Agent Configuration Snippet
                </label>
                <pre className="p-3 bg-black border border-[#27272a] rounded-sm font-mono text-[11px] text-zinc-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  {selectedSource.configSnippet}
                </pre>
              </div>

              <div className="pt-2 border-t border-[#222226]">
                <button
                  onClick={() => handleTestCollector(selectedSource.id)}
                  disabled={testingId === selectedSource.id}
                  className="w-full py-2 bg-[#ff3e3e] hover:bg-[#ff5555] text-black font-black font-mono text-xs uppercase tracking-wider rounded-sm transition flex items-center justify-center gap-2"
                >
                  <Zap className="w-4 h-4" />
                  <span>Send Synthetic Diagnostic Event</span>
                </button>
              </div>
            </div>
          )}

          {/* Interactive REST Ingest Sandbox */}
          <div className="p-5 bg-[#0a0a0c] border border-[#222226] rounded-sm space-y-3">
            <div className="flex items-center gap-2 border-b border-[#222226] pb-2">
              <Terminal className="w-4 h-4 text-[#ff3e3e]" />
              <h4 className="text-xs font-black uppercase tracking-wider text-white">Live Event Ingest Tester (POST /api/events)</h4>
            </div>

            <p className="text-[11px] text-zinc-400">
              Inject custom raw or structured JSON security logs directly into the SentinelX detection pipeline:
            </p>

            <textarea
              value={manualLogPayload}
              onChange={(e) => setManualLogPayload(e.target.value)}
              rows={8}
              className="w-full bg-black border border-[#27272a] rounded-sm p-2.5 font-mono text-xs text-zinc-200 focus:outline-none focus:border-[#ff3e3e] transition"
            />

            <button
              onClick={handleSendManualEvent}
              disabled={isSubmittingManual}
              className="w-full py-2 bg-[#18181b] hover:bg-[#27272a] border border-[#333] text-white font-mono text-xs font-bold uppercase tracking-wider rounded-sm transition flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <Send className={`w-3.5 h-3.5 text-blue-400 ${isSubmittingManual ? 'animate-spin' : ''}`} />
              <span>{isSubmittingManual ? 'INGESTING...' : 'SUBMIT REAL LOG PAYLOAD'}</span>
            </button>

            {manualResult && (
              <div
                className={`p-3 rounded-sm font-mono text-xs ${
                  manualResult.startsWith('[✓]')
                    ? 'bg-emerald-950/60 border border-emerald-700/50 text-emerald-300'
                    : 'bg-rose-950/60 border border-rose-700/50 text-rose-300'
                }`}
              >
                {manualResult}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
