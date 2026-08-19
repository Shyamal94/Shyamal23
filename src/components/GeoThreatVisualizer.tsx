import React, { useState } from 'react';
import { Globe, Shield, Radio, MapPin, AlertCircle, ArrowUpRight } from 'lucide-react';
import { SecurityIncident } from '../types';

interface GeoThreatVisualizerProps {
  incidents: SecurityIncident[];
  onSelectIncident: (inc: SecurityIncident) => void;
}

export const GeoThreatVisualizer: React.FC<GeoThreatVisualizerProps> = ({
  incidents,
  onSelectIncident,
}) => {
  const [selectedGeo, setSelectedGeo] = useState<SecurityIncident | null>(incidents[0] || null);

  // Simplified World Vector Points for threat origin representation
  const threatOrigins = incidents.map((inc) => ({
    incident: inc,
    x: ((inc.sourceGeo.lng + 180) / 360) * 100, // percentage for SVG
    y: ((90 - inc.sourceGeo.lat) / 180) * 100,
    color: inc.severity === 'CRITICAL' ? '#f43f5e' : inc.severity === 'HIGH' ? '#f59e0b' : '#38bdf8',
  }));

  return (
    <div className="bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-lg flex flex-col justify-between">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-[#ff3e3e]" />
          <h3 className="text-sm font-black uppercase tracking-wider text-white">Global Threat Ingress & C2 Matrix</h3>
        </div>
        <div className="flex items-center gap-3 text-[10px] font-mono uppercase tracking-wider">
          <span className="flex items-center gap-1.5 text-[#ff3e3e] font-bold">
            <span className="w-2 h-2 rounded-full bg-[#ff3e3e] animate-ping inline-block"></span>
            Active C2 Nodes ({incidents.length})
          </span>
        </div>
      </div>

      {/* Cyber Map Radar Canvas */}
      <div className="relative w-full h-44 bg-[#050505] rounded-sm border border-[#222226] overflow-hidden flex items-center justify-center">
        {/* Grid Background lines */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#27272a15_1px,transparent_1px),linear-gradient(to_bottom,#27272a15_1px,transparent_1px)] bg-[size:20px_20px]"></div>
        
        {/* Radar Ring Visuals */}
        <div className="absolute w-72 h-72 rounded-full border border-[#ff3e3e]/10 animate-pulse"></div>
        <div className="absolute w-44 h-44 rounded-full border border-[#ff3e3e]/15"></div>
        <div className="absolute w-20 h-20 rounded-full border border-[#ff3e3e]/20"></div>

        {/* Global Continental Outlines (Stylized Vector) */}
        <svg viewBox="0 0 1000 400" className="w-full h-full opacity-20 fill-zinc-600 stroke-zinc-500 stroke-[0.5]">
          {/* North America */}
          <path d="M 120 70 Q 200 60 260 90 Q 290 140 240 180 Q 180 200 130 150 Z" />
          {/* South America */}
          <path d="M 270 200 Q 340 230 320 310 Q 280 370 260 300 Z" />
          {/* Europe */}
          <path d="M 480 80 Q 550 70 570 120 Q 520 150 470 130 Z" />
          {/* Africa */}
          <path d="M 490 160 Q 580 170 560 270 Q 510 320 470 230 Z" />
          {/* Asia */}
          <path d="M 590 80 Q 750 70 820 140 Q 780 230 650 200 Z" />
          {/* Australia */}
          <path d="M 780 270 Q 860 270 850 330 Q 780 340 760 300 Z" />
        </svg>

        {/* Threat Ingress Markers */}
        {threatOrigins.map(({ incident, x, y, color }) => {
          const isSelected = selectedGeo?.id === incident.id;
          return (
            <div
              key={incident.id}
              style={{ left: `${Math.max(10, Math.min(90, x))}%`, top: `${Math.max(15, Math.min(85, y))}%` }}
              onClick={() => {
                setSelectedGeo(incident);
                onSelectIncident(incident);
              }}
              className="absolute -translate-x-1/2 -translate-y-1/2 cursor-pointer group z-20"
            >
              <div className="relative flex items-center justify-center">
                <span
                  style={{ backgroundColor: color }}
                  className="animate-ping absolute inline-flex h-4 w-4 rounded-full opacity-75"
                ></span>
                <span
                  style={{ backgroundColor: color }}
                  className={`relative inline-flex rounded-sm h-3 w-3 border-2 border-black shadow-md ${
                    isSelected ? 'ring-2 ring-white scale-125' : ''
                  }`}
                ></span>
              </div>

              {/* Tooltip on hover */}
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 hidden group-hover:block w-48 p-2 bg-[#0c0c0e] border border-[#333] rounded-sm text-[11px] shadow-2xl pointer-events-none z-30 font-mono">
                <div className="font-bold text-white flex items-center gap-1">
                  <span>{incident.sourceGeo.flag}</span>
                  <span>{incident.sourceGeo.city}, {incident.sourceGeo.country}</span>
                </div>
                <div className="text-zinc-400 text-[10px] mt-0.5">{incident.sourceIp}</div>
                <div className="text-[#ff3e3e] text-[10px] font-bold mt-1 truncate">{incident.title}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Node Summary strip */}
      {selectedGeo && (
        <div className="mt-3 p-3 rounded-sm bg-[#08080a] border border-[#222226] flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-3">
            <div className="text-xl">{selectedGeo.sourceGeo.flag}</div>
            <div>
              <div className="font-bold text-white flex items-center gap-2">
                <span>{selectedGeo.sourceGeo.city}, {selectedGeo.sourceGeo.country}</span>
                <span className="text-[#ff3e3e]">({selectedGeo.sourceIp})</span>
              </div>
              <div className="text-zinc-400 text-[10px] flex items-center gap-2 mt-0.5 uppercase tracking-wider">
                <span>Target: <strong className="text-zinc-200">{selectedGeo.targetHost}</strong></span>
                <span className="text-zinc-600">•</span>
                <span>Tactic: <strong className="text-amber-300">{selectedGeo.mitreTactic}</strong></span>
              </div>
            </div>
          </div>

          <button
            onClick={() => onSelectIncident(selectedGeo)}
            className="flex items-center gap-1 px-3 py-1.5 rounded-sm bg-[#ff3e3e] text-black hover:bg-[#ff5555] text-xs font-black uppercase tracking-wider transition"
          >
            <span>Triage</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
};
