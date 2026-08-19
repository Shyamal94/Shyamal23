import React, { useState } from 'react';
import { AlertTriangle, ShieldCheck, Zap, Lock, UserCheck, X } from 'lucide-react';
import { SOARPlaybook, SecurityIncident } from '../types';

interface SOARConfirmationModalProps {
  playbook: SOARPlaybook;
  targetIncident?: SecurityIncident | null;
  userRole: string;
  onConfirm: (notes: string) => void;
  onCancel: () => void;
}

export const SOARConfirmationModal: React.FC<SOARConfirmationModalProps> = ({
  playbook,
  targetIncident,
  userRole,
  onConfirm,
  onCancel,
}) => {
  const [notes, setNotes] = useState<string>('Authorized tier-3 emergency containment procedure.');
  const [understoodImpact, setUnderstoodImpact] = useState<boolean>(false);

  const targetHost = targetIncident?.targetHost || 'TARGET_ASSET';
  const sourceIp = targetIncident?.sourceIp || 'C2_IP';

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-[#0a0a0c] border border-[#ff3e3e]/60 rounded-sm shadow-2xl p-6 font-mono text-xs space-y-4">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-[#222226] pb-3">
          <div className="flex items-center gap-2">
            <span className="p-2 bg-rose-950/80 border border-rose-600/50 text-[#ff3e3e] rounded-sm">
              <AlertTriangle className="w-5 h-5 animate-pulse" />
            </span>
            <div>
              <span className="text-[10px] text-zinc-400 uppercase tracking-widest block font-bold">
                Analyst Authorization Required
              </span>
              <h3 className="text-sm font-black text-white uppercase">{playbook.name}</h3>
            </div>
          </div>
          <button onClick={onCancel} className="text-zinc-500 hover:text-white text-xs">
            ✕
          </button>
        </div>

        {/* Integration Check */}
        <div className="p-3 bg-black border border-[#27272a] rounded-sm space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-zinc-400 text-[11px]">Required Connector:</span>
            <span className="text-white font-bold">{playbook.requiredIntegration || 'EDR Sensor API'}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-zinc-400 text-[11px]">Integration Authorization:</span>
            <span className="px-1.5 py-0.5 bg-emerald-950/80 border border-emerald-600/40 text-emerald-400 font-bold rounded-sm text-[10px]">
              AUTHORIZED (SECURE)
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-zinc-400 text-[11px]">Executing Analyst Role:</span>
            <span className="text-blue-400 font-bold">{userRole}</span>
          </div>
        </div>

        {/* Target & Blast Radius Assessment */}
        <div className="p-3 bg-[#140b0b] border border-rose-900/40 rounded-sm space-y-1">
          <div className="text-[10px] font-black text-[#ff3e3e] uppercase tracking-wider">
            Operational Impact Assessment
          </div>
          <div className="text-zinc-300 text-[11px] leading-relaxed">
            Executing this playbook will apply an emergency network quarantine filter to host{' '}
            <strong className="text-white">{targetHost}</strong> and block traffic from IP{' '}
            <strong className="text-[#ff3e3e]">{sourceIp}</strong> across border firewalls.
          </div>
        </div>

        {/* Playbook Steps Summary */}
        <div className="space-y-1">
          <span className="text-[10px] text-zinc-400 uppercase tracking-wider block font-bold">
            Actions to be executed ({playbook.steps.length} Steps):
          </span>
          <div className="space-y-1 bg-black p-2.5 border border-[#222226] rounded-sm max-h-32 overflow-y-auto">
            {playbook.steps.map((s, idx) => (
              <div key={s.id} className="text-[11px] text-zinc-300 flex items-center gap-2">
                <span className="text-[#ff3e3e] font-bold">{idx + 1}.</span>
                <span>{s.name}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Analyst Notes */}
        <div>
          <label className="text-[10px] text-zinc-400 uppercase tracking-wider block mb-1 font-bold">
            Incident Commander / Analyst Authorization Notes:
          </label>
          <input
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            className="w-full bg-black border border-[#27272a] rounded-sm px-3 py-1.5 text-xs text-white focus:outline-none focus:border-[#ff3e3e]"
          />
        </div>

        {/* Mandatory checkbox */}
        <label className="flex items-center gap-2 text-zinc-300 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={understoodImpact}
            onChange={(e) => setUnderstoodImpact(e.target.checked)}
            className="rounded-sm accent-[#ff3e3e]"
          />
          <span className="text-[11px]">
            I confirm authority to execute this containment action on production assets.
          </span>
        </label>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-3 pt-2 border-t border-[#222226]">
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-[#18181b] hover:bg-[#27272a] border border-[#333] text-zinc-300 font-bold uppercase rounded-sm"
          >
            Cancel
          </button>
          <button
            disabled={!understoodImpact}
            onClick={() => onConfirm(notes)}
            className="px-5 py-2 bg-[#ff3e3e] hover:bg-[#ff5555] disabled:opacity-40 text-black font-black uppercase rounded-sm transition flex items-center gap-1.5 shadow-md"
          >
            <Zap className="w-4 h-4" />
            <span>CONFIRM & EXECUTE SOAR</span>
          </button>
        </div>
      </div>
    </div>
  );
};
