import React from 'react';
import {
  ShieldAlert,
  Activity,
  Terminal,
  Cpu,
  Database,
  Search,
  Zap,
  Radio,
  Play,
  FileText,
  Layers,
  Sparkles,
  AlertTriangle,
  Server,
  UserCheck,
  ToggleLeft,
  ToggleRight,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { UserRole } from '../types';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  openIncidentsCount: number;
  criticalCount: number;
  onSimulateThreat: (scenario: string) => void;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  isSimulating: boolean;
  isDemoMode: boolean;
  setIsDemoMode: (val: boolean) => void;
  userRole: UserRole;
  setUserRole: (role: UserRole) => void;
  wsConnected: boolean;
  liveEpsRate: number;
  activeSourcesCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  openIncidentsCount,
  criticalCount,
  onSimulateThreat,
  searchQuery,
  setSearchQuery,
  isSimulating,
  isDemoMode,
  setIsDemoMode,
  userRole,
  setUserRole,
  wsConnected,
  liveEpsRate,
  activeSourcesCount,
}) => {
  return (
    <header className="sticky top-0 z-40 bg-[#0a0a0c] border-b border-[#222226] text-[#e0e0e0]">
      {/* Top Banner Status Bar */}
      <div className="px-4 sm:px-8 py-2 bg-[#050505] border-b border-[#222226] flex items-center justify-between text-xs font-mono flex-wrap gap-2">
        <div className="flex items-center gap-3 sm:gap-5 flex-wrap tracking-wider uppercase text-[11px]">
          {/* WebSocket Live Telemetry Status */}
          <div className="flex items-center gap-1.5 font-bold">
            {wsConnected ? (
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <span>TELEMETRY: CONNECTED</span>
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-amber-400">
                <WifiOff className="w-3 h-3 animate-pulse" />
                <span>TELEMETRY: RECONNECTING</span>
              </span>
            )}
          </div>

          <span className="text-[#333] hidden sm:inline">|</span>

          {/* Mode Indicator & Switcher */}
          <div className="flex items-center gap-2">
            <span className="text-zinc-400 text-[10px]">ENVIRONMENT:</span>
            <button
              onClick={() => setIsDemoMode(!isDemoMode)}
              className={`flex items-center gap-1 px-2 py-0.5 rounded-sm font-black text-[10px] uppercase tracking-wider transition ${
                isDemoMode
                  ? 'bg-amber-950/80 text-amber-400 border border-amber-600/60'
                  : 'bg-emerald-950/80 text-emerald-400 border border-emerald-600/60'
              }`}
              title="Click to toggle between Live Ingestion and Demo Simulation mode"
            >
              {isDemoMode ? (
                <>
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                  <span>DEMO MODE (PRACTICE)</span>
                </>
              ) : (
                <>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                  <span>LIVE MODE (REAL LOGS)</span>
                </>
              )}
            </button>
          </div>

          <span className="text-[#333] hidden md:inline">|</span>

          <span className="text-zinc-400 hidden md:inline">
            INGRESS:{' '}
            <span className="text-[#ff3e3e] font-black">
              {liveEpsRate.toLocaleString()} EPS
            </span>
          </span>

          <span className="text-[#333] hidden lg:inline">|</span>

          <span className="text-zinc-400 hidden lg:inline">
            COLLECTORS:{' '}
            <span className="text-white font-bold">{activeSourcesCount} ACTIVE</span>
          </span>

          <span className="text-[#333] hidden xl:inline">|</span>

          <span className="text-zinc-400 hidden xl:inline">
            AI ENGINE: <span className="text-blue-400 font-bold">GEMINI 3.7 FLASH</span>
          </span>
        </div>

        {/* Right Controls: DEFCON, RBAC Role, Attack Injector */}
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm bg-[#1a0a0a] border border-[#ff3e3e]/40 text-[#ff3e3e] text-[10px] font-mono uppercase font-bold tracking-widest">
            <AlertTriangle className="w-3 h-3 text-[#ff3e3e] animate-pulse" />
            <span>DEFCON 2</span>
          </div>

          {/* User Role Switcher */}
          <div className="flex items-center gap-1 bg-[#121216] border border-[#333] rounded-sm px-2 py-0.5 text-[10px] font-mono text-zinc-300">
            <UserCheck className="w-3 h-3 text-blue-400" />
            <select
              value={userRole}
              onChange={(e) => setUserRole(e.target.value as UserRole)}
              className="bg-transparent text-white font-bold focus:outline-none cursor-pointer uppercase"
            >
              <option value="SOC_ADMIN" className="bg-[#0a0a0c]">SOC_ADMIN</option>
              <option value="TIER_3_ANALYST" className="bg-[#0a0a0c]">TIER_3_ANALYST</option>
              <option value="TIER_1_TRIAGE" className="bg-[#0a0a0c]">TIER_1_TRIAGE</option>
              <option value="INCIDENT_COMMANDER" className="bg-[#0a0a0c]">INCIDENT_CMD</option>
            </select>
          </div>

          {/* Simulate Attack Trigger (Interactive Practice) */}
          <div className="relative group">
            <button
              id="simulate-attack-trigger"
              disabled={isSimulating}
              className="flex items-center gap-1.5 px-3 py-1 rounded-sm bg-[#ff3e3e] hover:bg-[#ff5555] text-black font-black text-xs uppercase tracking-wider transition shadow-sm disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
              <span>{isSimulating ? 'SIMULATING...' : 'INJECT SCENARIO'}</span>
            </button>
            <div className="absolute right-0 mt-1 w-64 p-2 bg-[#0c0c0e] border border-[#333] rounded-sm shadow-2xl hidden group-hover:block z-50">
              <div className="text-[10px] font-black text-zinc-400 mb-1.5 px-1 uppercase tracking-[0.2em]">
                Simulate Security Scenario
              </div>
              <button
                onClick={() => onSimulateThreat('RANSOMWARE')}
                className="w-full text-left px-2.5 py-1.5 hover:bg-[#18181b] rounded-sm text-xs text-rose-300 hover:text-white flex items-center justify-between"
              >
                <span>ALPHV Ransomware Ingress</span>
                <span className="text-[9px] font-mono px-1 py-0.2 bg-[#ff3e3e]/20 text-[#ff3e3e] border border-[#ff3e3e]/40 rounded-sm font-bold">
                  CRITICAL
                </span>
              </button>
              <button
                onClick={() => onSimulateThreat('COBALT_STRIKE')}
                className="w-full text-left px-2.5 py-1.5 hover:bg-[#18181b] rounded-sm text-xs text-amber-300 hover:text-white flex items-center justify-between mt-1"
              >
                <span>Cobalt Strike C2 Beacon</span>
                <span className="text-[9px] font-mono px-1 py-0.2 bg-amber-950/60 text-amber-400 border border-amber-800 rounded-sm font-bold">
                  HIGH
                </span>
              </button>
              <button
                onClick={() => onSimulateThreat('DNS_EXFIL')}
                className="w-full text-left px-2.5 py-1.5 hover:bg-[#18181b] rounded-sm text-xs text-blue-300 hover:text-white flex items-center justify-between mt-1"
              >
                <span>DNS Tunneling Exfiltration</span>
                <span className="text-[9px] font-mono px-1 py-0.2 bg-blue-950/60 text-blue-400 border border-blue-800 rounded-sm font-bold">
                  HIGH
                </span>
              </button>
              <button
                onClick={() => onSimulateThreat('PASS_THE_HASH')}
                className="w-full text-left px-2.5 py-1.5 hover:bg-[#18181b] rounded-sm text-xs text-purple-300 hover:text-white flex items-center justify-between mt-1"
              >
                <span>Pass-the-Hash Movement</span>
                <span className="text-[9px] font-mono px-1 py-0.2 bg-purple-950/60 text-purple-400 border border-purple-800 rounded-sm font-bold">
                  CRITICAL
                </span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Header Nav */}
      <div className="px-4 sm:px-8 py-3 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-[#ff3e3e] rounded-sm flex items-center justify-center font-black text-black text-lg tracking-tighter">
            X
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl font-black tracking-tighter uppercase text-white">
                SENTINEL<span className="text-[#ff3e3e]">X</span>
              </span>
              <span className="px-1.5 py-0.5 rounded-sm bg-[#18181b] border border-[#333] text-[9px] font-mono text-zinc-300 font-bold uppercase tracking-widest">
                SOC &amp; DFIR ENGINE
              </span>
            </div>
            <p className="text-[10px] text-zinc-400 uppercase tracking-[0.2em] font-mono hidden sm:block">
              Real-Time Security Operations &amp; Forensic Defense
            </p>
          </div>
        </div>

        {/* Global Search Bar */}
        <div className="flex-1 max-w-md hidden md:block">
          <div className="relative">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="GLOBAL HUNT: IP, SHA-256, CVE, Host, MITRE ID (e.g. T1059, 185.220...)"
              className="w-full bg-[#08080a] border border-[#27272a] rounded-sm pl-9 pr-3 py-1.5 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-[#ff3e3e] font-mono transition"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0 font-mono text-xs uppercase tracking-wider">
          <button
            id="nav-threat-ops"
            onClick={() => setActiveTab('threat-ops')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
              activeTab === 'threat-ops'
                ? 'bg-[#ff3e3e] text-black shadow-sm'
                : 'text-zinc-400 hover:text-white hover:bg-[#18181b]'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span className="whitespace-nowrap">Threat Ops</span>
            {openIncidentsCount > 0 && (
              <span
                className={`px-1.5 py-0.2 rounded-sm text-[9px] font-black ${
                  activeTab === 'threat-ops'
                    ? 'bg-black text-[#ff3e3e]'
                    : criticalCount > 0
                    ? 'bg-[#ff3e3e] text-black'
                    : 'bg-amber-500 text-black'
                }`}
              >
                {openIncidentsCount}
              </span>
            )}
          </button>

          <button
            id="nav-threat-hunt"
            onClick={() => setActiveTab('hunt')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
              activeTab === 'hunt'
                ? 'bg-[#ff3e3e] text-black shadow-sm'
                : 'text-zinc-400 hover:text-white hover:bg-[#18181b]'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            <span className="whitespace-nowrap">Threat Hunt</span>
          </button>

          <button
            id="nav-data-sources"
            onClick={() => setActiveTab('data-sources')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
              activeTab === 'data-sources'
                ? 'bg-[#ff3e3e] text-black shadow-sm'
                : 'text-zinc-400 hover:text-white hover:bg-[#18181b]'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span className="whitespace-nowrap">Data Sources</span>
          </button>

          <button
            id="nav-soar-engine"
            onClick={() => setActiveTab('soar')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
              activeTab === 'soar'
                ? 'bg-[#ff3e3e] text-black shadow-sm'
                : 'text-zinc-400 hover:text-white hover:bg-[#18181b]'
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            <span className="whitespace-nowrap">SOAR</span>
          </button>

          <button
            id="nav-forensics-lab"
            onClick={() => setActiveTab('forensics')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
              activeTab === 'forensics'
                ? 'bg-[#ff3e3e] text-black shadow-sm'
                : 'text-zinc-400 hover:text-white hover:bg-[#18181b]'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span className="whitespace-nowrap">Forensics</span>
          </button>

          <button
            id="nav-mitre-matrix"
            onClick={() => setActiveTab('mitre')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
              activeTab === 'mitre'
                ? 'bg-[#ff3e3e] text-black shadow-sm'
                : 'text-zinc-400 hover:text-white hover:bg-[#18181b]'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span className="whitespace-nowrap">MITRE ATT&CK</span>
          </button>

          <button
            id="nav-rule-studio"
            onClick={() => setActiveTab('rules')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
              activeTab === 'rules'
                ? 'bg-[#ff3e3e] text-black shadow-sm'
                : 'text-zinc-400 hover:text-white hover:bg-[#18181b]'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span className="whitespace-nowrap">Rules</span>
          </button>

          <button
            id="nav-ai-copilot"
            onClick={() => setActiveTab('ai-copilot')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
              activeTab === 'ai-copilot'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-zinc-400 hover:text-blue-400 hover:bg-blue-950/20'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-blue-400" />
            <span className="whitespace-nowrap">AI Co-Pilot</span>
          </button>
        </div>
      </div>
    </header>
  );
};
