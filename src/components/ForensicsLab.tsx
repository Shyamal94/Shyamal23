import React, { useState } from 'react';
import { 
  Cpu, 
  Binary, 
  FileCode, 
  Terminal, 
  Sparkles, 
  Upload, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  Eye, 
  Search, 
  Copy, 
  FileSearch,
  Activity,
  Layers,
  ArrowRight
} from 'lucide-react';
import { ForensicArtifact, IOCItem } from '../types';
import { FORENSIC_ARTIFACTS } from '../data/mockData';
import { analyzeArtifactWithAI } from '../services/api';

export const ForensicsLab: React.FC = () => {
  const [artifacts, setArtifacts] = useState<ForensicArtifact[]>(FORENSIC_ARTIFACTS);
  const [selectedArtifact, setSelectedArtifact] = useState<ForensicArtifact>(artifacts[0]);
  const [viewMode, setViewMode] = useState<'hex' | 'disassembly' | 'strings' | 'behavior' | 'ai-report'>('hex');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [customInputText, setCustomInputText] = useState('');
  const [showUploadModal, setShowUploadModal] = useState(false);

  const handleRunAIAnalysis = async () => {
    if (!selectedArtifact || isAnalyzing) return;
    try {
      setIsAnalyzing(true);
      const res = await analyzeArtifactWithAI(selectedArtifact);
      if (res.success && res.report) {
        const updated = {
          ...selectedArtifact,
          aiForensicReport: res.report,
        };
        setSelectedArtifact(updated);
        setArtifacts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
        setViewMode('ai-report');
      }
    } catch (err) {
      console.error('Forensic analysis error:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCreateCustomArtifact = () => {
    if (!customInputText.trim()) return;
    const newArt: ForensicArtifact = {
      id: `art-${Math.floor(100 + Math.random() * 900)}`,
      name: 'user_injected_sample.hex',
      artifactType: 'POWERSHELL_PAYLOAD',
      fileSize: `${(customInputText.length / 1024).toFixed(1)} KB`,
      hashSha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
      hashMd5: '1234567890abcdef1234567890abcdef',
      description: 'User submitted suspicious artifact payload for instant digital forensics disassembly.',
      entropy: 7.21,
      sourceHost: 'CUSTOM-UPLOAD-SANDBOX',
      collectedAt: new Date().toUTCString(),
      hexPreview: `00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............\n00000010: 2465 6e63 203d 2022 4a41 4247 4147 6341  $enc = "JABGAGcA...`,
      extractedStrings: [
        'powershell.exe -nop -w hidden -enc',
        'VirtualAllocEx',
        'Invoke-Expression',
        'http://malicious-c2-node.io/stage'
      ],
      decompiledCode: customInputText,
      behavioralTraces: [
        { category: 'PROCESS_EXEC', action: 'Invoke Script', target: 'powershell.exe', risk: 'HIGH' },
        { category: 'NETWORK', action: 'ConnectSocket', target: 'malicious-c2-node.io:443', risk: 'HIGH' }
      ],
      iocs: [
        { type: 'DOMAIN', value: 'malicious-c2-node.io', reputation: 'MALICIOUS', sourceContext: 'Injected script C2' }
      ],
      yaraMatches: ['Custom_Injected_Stager_Rule']
    };

    setArtifacts([newArt, ...artifacts]);
    setSelectedArtifact(newArt);
    setShowUploadModal(false);
    setCustomInputText('');
  };

  const copyText = (txt: string) => {
    navigator.clipboard.writeText(txt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12 font-mono">
      {/* Top Banner */}
      <div className="p-5 bg-[#0a0a0c] border border-[#222226] rounded-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-sm bg-[#ff3e3e]/10 text-[#ff3e3e] border border-[#ff3e3e]/30">
              <Cpu className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-black text-white uppercase tracking-wider">Digital Forensics & Binary Reverse-Engineering Lab</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1 max-w-2xl font-sans leading-relaxed">
            Inspect raw memory byte streams, examine PCAP network dumps, decompile obfuscated scripts, evaluate entropy, and leverage Gemini for deep binary reverse-engineering.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 bg-[#18181b] hover:bg-[#27272a] text-white rounded-sm text-xs font-black uppercase tracking-wider border border-[#333] transition"
          >
            <Upload className="w-4 h-4 text-[#ff3e3e]" />
            <span>Import Raw Artifact</span>
          </button>
        </div>
      </div>

      {/* Main Forensics Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Artifacts Catalog (Left 4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-black text-white uppercase tracking-wider flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-[#ff3e3e]" />
              <span>Collected Evidence Vault ({artifacts.length})</span>
            </h3>
          </div>

          <div className="space-y-3">
            {artifacts.map((art) => {
              const isSelected = selectedArtifact.id === art.id;
              return (
                <div
                  key={art.id}
                  onClick={() => setSelectedArtifact(art)}
                  className={`p-4 rounded-sm border cursor-pointer transition ${
                    isSelected
                      ? 'bg-[#150a0b] border-[#ff3e3e] shadow-lg'
                      : 'bg-[#0a0a0c] border-[#222226] hover:border-[#444]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[#ff3e3e] text-[10px] font-black px-2 py-0.5 rounded-sm bg-[#ff3e3e]/10 border border-[#ff3e3e]/30 uppercase">
                      {art.artifactType}
                    </span>
                    <span className="text-[11px] text-zinc-400 font-mono">{art.fileSize}</span>
                  </div>

                  <h4 className="font-bold text-white text-sm mt-2 truncate font-mono">{art.name}</h4>
                  <p className="text-xs text-zinc-400 mt-1 line-clamp-2 font-sans">{art.description}</p>

                  <div className="mt-3 pt-3 border-t border-[#1f1f23] flex items-center justify-between text-[11px] text-zinc-400 font-mono">
                    <span>
                      Entropy: <strong className={art.entropy > 7.0 ? 'text-[#ff3e3e]' : 'text-emerald-400'}>{art.entropy}/8.0</strong>
                    </span>
                    <span>Host: <strong className="text-zinc-300">{art.sourceHost}</strong></span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Deep Disassembly / Hex / AI Inspector (Right 8 cols) */}
        <div className="lg:col-span-8 bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-lg flex flex-col space-y-4">
          {/* Artifact Header Info */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-[#222226]">
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black text-white font-mono">{selectedArtifact.name}</h3>
                <span className="text-[10px] px-2 py-0.5 bg-[#18181b] border border-[#333] rounded-sm text-zinc-300 font-mono">
                  SHA-256: {selectedArtifact.hashSha256.substring(0, 16)}...
                </span>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5 font-sans">{selectedArtifact.description}</p>
            </div>

            <button
              onClick={handleRunAIAnalysis}
              disabled={isAnalyzing}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-sm bg-blue-600 hover:bg-blue-500 text-white text-xs font-black uppercase tracking-wider shadow transition disabled:opacity-50"
            >
              <Sparkles className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
              <span>{isAnalyzing ? 'Reverse Engineering...' : 'Gemini AI Disassembly'}</span>
            </button>
          </div>

          {/* View Modes */}
          <div className="flex items-center justify-between gap-2 overflow-x-auto pb-1 uppercase tracking-wider text-xs">
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setViewMode('hex')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                  viewMode === 'hex' ? 'bg-[#ff3e3e] text-black shadow' : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Binary className="w-3.5 h-3.5" />
                <span>Hex Stream</span>
              </button>
              <button
                onClick={() => setViewMode('disassembly')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                  viewMode === 'disassembly' ? 'bg-[#ff3e3e] text-black shadow' : 'text-zinc-400 hover:text-white'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>Disassembly</span>
              </button>
              <button
                onClick={() => setViewMode('strings')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                  viewMode === 'strings' ? 'bg-[#ff3e3e] text-black shadow' : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Search className="w-3.5 h-3.5" />
                <span>Strings ({selectedArtifact.extractedStrings.length})</span>
              </button>
              <button
                onClick={() => setViewMode('behavior')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                  viewMode === 'behavior' ? 'bg-[#ff3e3e] text-black shadow' : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Behavior</span>
              </button>
              <button
                onClick={() => setViewMode('ai-report')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-bold transition ${
                  viewMode === 'ai-report' ? 'bg-blue-600 text-white shadow' : 'text-zinc-400 hover:text-blue-400'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>AI Report</span>
              </button>
            </div>

            <button
              onClick={() => copyText(selectedArtifact.hexPreview || selectedArtifact.decompiledCode || '')}
              className="flex items-center gap-1 px-2.5 py-1 rounded-sm bg-[#18181b] hover:bg-[#27272a] text-zinc-300 text-[10px] font-mono border border-[#333] transition uppercase"
            >
              <Copy className="w-3 h-3" />
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>

          {/* View Content Display */}
          <div className="flex-1 min-h-[420px] bg-[#050505] border border-[#222226] rounded-sm p-4 overflow-x-auto text-xs font-mono">
            {viewMode === 'hex' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between text-[11px] text-zinc-400 pb-2 border-b border-[#222226]">
                  <span>Offset (h) -- 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F</span>
                  <span>Decoded Text</span>
                </div>
                <pre className="text-zinc-300 leading-relaxed overflow-x-auto selection:bg-[#ff3e3e] selection:text-black">
                  {selectedArtifact.hexPreview}
                </pre>
              </div>
            )}

            {viewMode === 'disassembly' && (
              <div className="space-y-2">
                <div className="text-[11px] text-zinc-400 pb-2 border-b border-[#222226] uppercase">
                  SentinelX Binary Decompiler (Ghidra IR Representation)
                </div>
                <pre className="text-emerald-400 leading-relaxed overflow-x-auto">
                  {selectedArtifact.decompiledCode || '// No decompilation stream generated.'}
                </pre>
              </div>
            )}

            {viewMode === 'strings' && (
              <div className="space-y-2">
                <div className="text-[11px] text-zinc-400 pb-2 border-b border-[#222226] uppercase">
                  ASCII & Unicode Strings with High Information Density
                </div>
                <div className="space-y-1">
                  {selectedArtifact.extractedStrings.map((str, i) => (
                    <div key={i} className="p-2 bg-[#08080a] rounded-sm border border-[#1f1f23] text-zinc-200 flex items-center justify-between">
                      <span>{str}</span>
                      <span className="text-[10px] text-zinc-500 font-mono">Len: {str.length}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {viewMode === 'behavior' && (
              <div className="space-y-3">
                <div className="text-[11px] text-zinc-400 pb-2 border-b border-[#222226] uppercase">
                  Dynamic Execution Emulation & API Hook Intercepts
                </div>
                <div className="space-y-2">
                  {selectedArtifact.behavioralTraces.map((trace, i) => (
                    <div key={i} className="p-2.5 bg-[#08080a] rounded-sm border border-[#222226] flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded-sm text-[10px] bg-[#18181b] text-blue-400 font-bold border border-[#333]">
                          {trace.category}
                        </span>
                        <span className="text-zinc-200 font-bold">{trace.action}</span>
                        <span className="text-zinc-400">→ {trace.target}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded-sm text-[10px] font-black uppercase bg-[#ff3e3e] text-black">
                        {trace.risk} RISK
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {viewMode === 'ai-report' && (
              <div className="space-y-4 font-sans text-xs">
                {!selectedArtifact.aiForensicReport ? (
                  <div className="text-center py-12 text-zinc-400 font-mono">
                    <Sparkles className="w-8 h-8 text-blue-400 mx-auto mb-2 animate-pulse" />
                    <p className="uppercase">No AI reverse-engineering report generated yet.</p>
                    <button
                      onClick={handleRunAIAnalysis}
                      className="mt-3 px-4 py-1.5 rounded-sm bg-blue-600 hover:bg-blue-500 text-white font-black text-xs uppercase tracking-wider"
                    >
                      Run Gemini Disassembly Now
                    </button>
                  </div>
                ) : (
                  <div className="space-y-4 text-zinc-200">
                    <div className="p-3.5 bg-[#080d1a] border border-blue-900/60 rounded-sm space-y-1.5">
                      <div className="font-bold text-blue-400 text-xs uppercase tracking-wider font-mono">
                        Binary Architecture & Overview
                      </div>
                      <p className="text-xs text-zinc-200 leading-relaxed font-sans">
                        {selectedArtifact.aiForensicReport.overview}
                      </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm space-y-2">
                        <div className="font-bold text-white text-xs uppercase tracking-wider font-mono">
                          Identified Malicious Capabilities
                        </div>
                        <ul className="space-y-1.5 list-disc pl-4 text-zinc-300 text-xs font-sans">
                          {selectedArtifact.aiForensicReport.capabilities?.map((c, i) => (
                            <li key={i}>{c}</li>
                          ))}
                        </ul>
                      </div>

                      <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm space-y-2">
                        <div className="font-bold text-[#ff3e3e] text-xs uppercase tracking-wider font-mono">
                          Anti-Analysis & Sandbox Evasion
                        </div>
                        <ul className="space-y-1.5 list-disc pl-4 text-zinc-300 text-xs font-sans">
                          {selectedArtifact.aiForensicReport.antiAnalysisTechniques?.map((a, i) => (
                            <li key={i}>{a}</li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm space-y-1.5">
                      <div className="font-bold text-amber-400 text-xs uppercase tracking-wider font-mono">
                        Extracted C2 Infrastructure
                      </div>
                      <div className="flex flex-wrap gap-2 pt-1 font-mono">
                        {selectedArtifact.aiForensicReport.c2Infrastructure?.map((c2, i) => (
                          <span key={i} className="px-2.5 py-1 bg-[#15120a] border border-amber-800/80 rounded-sm text-amber-300 text-xs font-bold">
                            {c2}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm space-y-1.5">
                      <div className="font-bold text-emerald-400 text-xs uppercase tracking-wider font-mono">
                        Forensic Conclusion & Attribution
                      </div>
                      <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                        {selectedArtifact.aiForensicReport.forensicConclusion}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Upload/Paste Custom Artifact Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-sm flex items-center justify-center p-4 font-mono">
          <div className="bg-[#0a0a0c] border border-[#222226] rounded-sm w-full max-w-2xl p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-black text-white flex items-center gap-2 uppercase tracking-wider">
              <Upload className="w-5 h-5 text-[#ff3e3e]" />
              <span>Import Threat Payload / Script / Hex Stream</span>
            </h3>
            <p className="text-xs text-zinc-400 font-sans leading-relaxed">
              Paste obfuscated PowerShell, Bash shellcode, Base64 strings, or raw Hex bytes to load into the sandbox.
            </p>

            <textarea
              value={customInputText}
              onChange={(e) => setCustomInputText(e.target.value)}
              placeholder="Paste raw shellcode, PowerShell payload, or hex dump here..."
              rows={8}
              className="w-full bg-[#050505] border border-[#222226] rounded-sm p-3 font-mono text-xs text-white placeholder-zinc-600 focus:outline-none focus:border-[#ff3e3e]"
            ></textarea>

            <div className="flex items-center justify-end gap-2 uppercase text-xs">
              <button
                onClick={() => setShowUploadModal(false)}
                className="px-4 py-1.5 bg-[#18181b] hover:bg-[#27272a] text-zinc-300 rounded-sm font-bold border border-[#333]"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateCustomArtifact}
                disabled={!customInputText.trim()}
                className="px-4 py-1.5 bg-[#ff3e3e] hover:bg-[#ff5555] text-black rounded-sm font-black disabled:opacity-50"
              >
                Load into Forensics Lab
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
