import React, { useState } from 'react';
import { Layers, ShieldCheck, AlertTriangle, Search, ExternalLink, Activity, Info } from 'lucide-react';
import { MitreTechnique, SecurityIncident } from '../types';
import { MITRE_MATRIX } from '../data/mockData';

interface MitreMatrixProps {
  incidents: SecurityIncident[];
  onSelectTechnique?: (tech: MitreTechnique) => void;
}

export const MitreMatrix: React.FC<MitreMatrixProps> = ({ incidents }) => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(MITRE_MATRIX[0]);
  const [searchTerm, setSearchTerm] = useState('');

  // Group by tactic
  const tactics = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
  ];

  const filteredMatrix = MITRE_MATRIX.filter((t) => {
    if (!searchTerm) return true;
    const q = searchTerm.toLowerCase();
    return t.name.toLowerCase().includes(q) || t.id.toLowerCase().includes(q) || t.tactic.toLowerCase().includes(q);
  });

  return (
    <div className="space-y-6 pb-12 font-mono">
      {/* Top Banner */}
      <div className="p-5 bg-[#0a0a0c] border border-[#222226] rounded-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-sm bg-[#ff3e3e]/10 text-[#ff3e3e] border border-[#ff3e3e]/30">
              <Layers className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-black text-white uppercase tracking-wider">MITRE ATT&CK Enterprise Matrix Navigator</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1 max-w-2xl font-sans leading-relaxed">
            Correlate enterprise telemetry against adversary tactics, techniques, and procedures (TTPs). Highlight active intrusions and uncover detection blindspots.
          </p>
        </div>

        <div className="w-full md:w-72">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter TTP (e.g. T1059, Injection...)"
              className="w-full bg-[#050505] border border-[#333] rounded-sm pl-8 pr-3 py-1.5 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-[#ff3e3e] uppercase"
            />
          </div>
        </div>
      </div>

      {/* 12-Column MITRE Matrix Board */}
      <div className="bg-[#0a0a0c] border border-[#222226] rounded-sm p-4 shadow-2xl overflow-x-auto">
        <div className="min-w-[1200px] grid grid-cols-12 gap-2 text-xs">
          {tactics.map((tactic) => {
            const techniques = filteredMatrix.filter((t) => t.tactic.toLowerCase().includes(tactic.toLowerCase()));
            return (
              <div key={tactic} className="space-y-2">
                <div className="p-2 bg-[#050505] border border-[#222226] rounded-sm text-center">
                  <div className="font-black text-[10px] text-white uppercase leading-tight truncate">{tactic}</div>
                  <div className="text-[9px] text-zinc-500 mt-0.5 uppercase font-bold">{techniques.length} Techniques</div>
                </div>

                <div className="space-y-1.5">
                  {techniques.length === 0 ? (
                    <div className="p-2 bg-[#050505] rounded-sm border border-dashed border-[#222226] text-[9px] text-zinc-600 text-center uppercase font-bold">
                      No matches
                    </div>
                  ) : (
                    techniques.map((tech) => {
                      const isSelected = selectedTechnique?.id === tech.id;
                      const hasActiveIncidents = tech.incidentCount > 0;
                      return (
                        <div
                          key={tech.id}
                          onClick={() => setSelectedTechnique(tech)}
                          className={`p-2 rounded-sm border cursor-pointer transition ${
                            isSelected
                              ? 'bg-[#150a0b] border-[#ff3e3e] text-white shadow-lg'
                              : hasActiveIncidents
                              ? 'bg-[#150a0b] border-[#ff3e3e]/40 text-zinc-200 hover:border-[#ff3e3e]'
                              : 'bg-[#050505] border-[#222226] text-zinc-300 hover:border-[#444]'
                          }`}
                        >
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <span className="text-[#ff3e3e] font-black">{tech.id}</span>
                            {hasActiveIncidents && (
                              <span className="w-1.5 h-1.5 rounded-full bg-[#ff3e3e] animate-ping"></span>
                            )}
                          </div>
                          <div className="text-[10px] font-bold mt-1 leading-snug line-clamp-2 uppercase">
                            {tech.name}
                          </div>
                          <div className="mt-1 flex items-center justify-between text-[9px] text-zinc-400 font-mono">
                            <span>{tech.activeDetections} det.</span>
                            <span className={tech.riskScore > 90 ? 'text-[#ff3e3e] font-black' : 'text-amber-400 font-bold'}>
                              {tech.riskScore}%
                            </span>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Technique Detail Card */}
      {selectedTechnique && (
        <div className="bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-2xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#222226]">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs font-black px-2.5 py-1 rounded-sm bg-[#ff3e3e]/10 border border-[#ff3e3e]/30 text-[#ff3e3e]">
                {selectedTechnique.id}
              </span>
              <div>
                <h3 className="text-base font-black text-white uppercase tracking-wider">{selectedTechnique.name}</h3>
                <span className="text-xs text-zinc-400 font-mono uppercase">Tactic: {selectedTechnique.tactic}</span>
              </div>
            </div>

            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="px-3 py-1 rounded-sm bg-[#050505] border border-[#222226] text-zinc-300">
                Active SIEM Detections: <strong className="text-blue-400 font-bold">{selectedTechnique.activeDetections}</strong>
              </span>
              <span className="px-3 py-1 rounded-sm bg-[#150a0b] border border-[#ff3e3e]/30 text-[#ff3e3e]">
                Risk Score: <strong className="font-black">{selectedTechnique.riskScore}/100</strong>
              </span>
            </div>
          </div>

          <p className="text-xs text-zinc-300 leading-relaxed font-sans">{selectedTechnique.description}</p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm space-y-1.5">
              <div className="text-xs font-black text-emerald-400 uppercase tracking-wider">Recommended Defensive Controls</div>
              <ul className="text-xs text-zinc-400 space-y-1 list-disc pl-4 font-sans">
                <li>Deploy SentinelX Process Tree Monitor to detect anomalous parent-child execution.</li>
                <li>Enable Microsoft Attack Surface Reduction (ASR) rules for Win32 API abuse.</li>
                <li>Enforce Zero-Trust network microsegmentation on high-value asset subnets.</li>
              </ul>
            </div>

            <div className="p-3.5 bg-[#050505] border border-[#222226] rounded-sm space-y-1.5">
              <div className="text-xs font-black text-blue-400 uppercase tracking-wider">Correlated Incidents ({selectedTechnique.incidentCount})</div>
              <p className="text-xs text-zinc-400 font-sans">
                This technique is observed in active intrusion sets. Check Threat Operations for real-time telemetry alerts matching <span className="font-mono text-white font-bold">{selectedTechnique.id}</span>.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
