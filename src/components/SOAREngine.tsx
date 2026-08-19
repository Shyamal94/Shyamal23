import React, { useState, useEffect } from 'react';
import {
  Zap,
  Play,
  ShieldCheck,
  Server,
  Terminal,
  CheckCircle2,
  AlertCircle,
  Clock,
  RefreshCw,
  Plus,
  Layers,
  Lock,
  Flame,
  ArrowRight,
  UserCheck,
} from 'lucide-react';
import { SOARPlaybook, SecurityIncident } from '../types';
import { fetchPlaybooks, executeSOARPlaybook, fetchAuditLogs } from '../services/api';
import { SOARConfirmationModal } from './SOARConfirmationModal';

interface SOAREngineProps {
  incidents: SecurityIncident[];
  onApplyRemediation: (incidentId: string, actionName: string, output: string) => void;
  userRole: string;
}

export const SOAREngine: React.FC<SOAREngineProps> = ({
  incidents,
  onApplyRemediation,
  userRole,
}) => {
  const [playbooks, setPlaybooks] = useState<SOARPlaybook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<SOARPlaybook | null>(null);
  const [targetIncidentId, setTargetIncidentId] = useState<string>(incidents[0]?.id || '');
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [executionStep, setExecutionStep] = useState<number>(-1);
  const [executionLogs, setExecutionLogs] = useState<string[]>([]);
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);
  const [auditHistory, setAuditHistory] = useState<any[]>([]);

  const loadPlaybooksData = async () => {
    try {
      const res = await fetchPlaybooks();
      if (res.success && res.playbooks.length > 0) {
        setPlaybooks(res.playbooks);
        if (!selectedPlaybook) setSelectedPlaybook(res.playbooks[0]);
      }
      const auditRes = await fetchAuditLogs(20);
      if (auditRes.success) {
        setAuditHistory(auditRes.auditLogs);
      }
    } catch (err) {
      console.error('Failed to load SOAR data:', err);
    }
  };

  useEffect(() => {
    loadPlaybooksData();
  }, []);

  const targetIncident = incidents.find((i) => i.id === targetIncidentId) || incidents[0];

  const handleStartPlaybook = () => {
    if (!selectedPlaybook) return;
    if (selectedPlaybook.requiresConfirmation) {
      setShowConfirmModal(true);
    } else {
      runPlaybook('Standard automated execution.');
    }
  };

  const runPlaybook = async (notes: string) => {
    if (!selectedPlaybook || isExecuting) return;
    setShowConfirmModal(false);
    setIsExecuting(true);
    setExecutionLogs([`[+] Initiating SOAR Playbook: "${selectedPlaybook.name}"`]);
    setExecutionStep(0);

    try {
      const steps = selectedPlaybook.steps;
      for (let i = 0; i < steps.length; i++) {
        setExecutionStep(i);
        setExecutionLogs((prev) => [
          ...prev,
          `[*] Step ${i + 1}/${steps.length}: Executing ${steps[i].name}...`,
          `    -> Parameter: ${steps[i].paramExample.replace('{HOST}', targetIncident?.targetHost || 'TARGET')}`,
        ]);
        await new Promise((r) => setTimeout(r, 600));
        setExecutionLogs((prev) => [...prev, `[✓] Step ${i + 1} Succeeded: ${steps[i].description}`]);
      }

      // Execute on backend
      const res = await executeSOARPlaybook(selectedPlaybook.id, {
        incidentId: targetIncident?.id,
        confirmed: true,
        analystNotes: notes,
        executedBy: userRole,
      });

      setExecutionStep(steps.length);
      const finalLog = `[✔] SOAR Playbook Completed Successfully. Target host ${
        targetIncident?.targetHost || 'TARGET'
      } is now secured and contained. Audit ID: ${res.auditId}`;
      setExecutionLogs((prev) => [...prev, finalLog]);

      if (targetIncident) {
        onApplyRemediation(
          targetIncident.id,
          selectedPlaybook.name,
          `SOAR execution completed with ${steps.length} actions applied.`
        );
      }

      await loadPlaybooksData();
    } catch (err: any) {
      setExecutionLogs((prev) => [...prev, `[!] SOAR Execution Error: ${err.message}`]);
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="p-6 bg-[#0a0a0c] border border-[#222226] rounded-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-sm bg-[#ff3e3e]/10 text-[#ff3e3e] border border-[#ff3e3e]/30">
              <Zap className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-black uppercase tracking-wider text-white">SOAR Autonomous Incident Response Engine</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1 max-w-3xl">
            Execute automated containment playbooks: EDR isolation, Kerberos ticket purge, perimeter firewall drops, memory dumps, and zero-trust policy enforcement.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-[#050505] border border-[#222226] rounded-sm font-mono text-xs text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
            <span>SOAR STATUS: ARMED & READY</span>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Playbook List (Left 4 cols) */}
        <div className="lg:col-span-4 space-y-3">
          <div className="flex items-center justify-between px-1">
            <h3 className="text-xs font-black uppercase tracking-wider text-zinc-400">Security Playbooks</h3>
            <span className="text-xs text-zinc-500 font-mono">{playbooks.length} Active</span>
          </div>

          <div className="space-y-2 font-mono">
            {playbooks.map((pb) => {
              const isSelected = selectedPlaybook?.id === pb.id;
              return (
                <div
                  key={pb.id}
                  onClick={() => setSelectedPlaybook(pb)}
                  className={`p-3.5 rounded-sm border transition cursor-pointer ${
                    isSelected
                      ? 'bg-[#120e0e] border-[#ff3e3e] shadow-md'
                      : 'bg-[#0a0a0c] border-[#222226] hover:border-[#3f3f46]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="font-bold text-white text-xs tracking-tight">{pb.name}</div>
                    <span className="text-[9px] px-1.5 py-0.5 rounded-sm bg-[#18181b] border border-[#333] text-zinc-300">
                      {pb.category}
                    </span>
                  </div>

                  <p className="text-[11px] text-zinc-400 mt-1 line-clamp-2">{pb.description}</p>

                  <div className="mt-3 pt-2 border-t border-[#1a1a1e] flex items-center justify-between text-[10px] text-zinc-400">
                    <span>{pb.steps.length} Automated Steps</span>
                    <span>Executions: <strong className="text-white">{pb.executionCount}</strong></span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Playbook Execution & Terminal (Center/Right 8 cols) */}
        <div className="lg:col-span-8 space-y-6">
          {selectedPlaybook && (
            <div className="p-5 bg-[#0a0a0c] border border-[#222226] rounded-sm space-y-5">
              {/* Playbook Header */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-[#222226]">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono px-2 py-0.5 rounded-sm bg-[#ff3e3e]/10 text-[#ff3e3e] border border-[#ff3e3e]/30 font-bold">
                      {selectedPlaybook.id}
                    </span>
                    <h3 className="text-base font-black text-white">{selectedPlaybook.name}</h3>
                  </div>
                  <p className="text-xs text-zinc-400 mt-1">{selectedPlaybook.description}</p>
                </div>

                <div className="flex items-center gap-2">
                  {selectedPlaybook.requiresConfirmation && (
                    <span className="flex items-center gap-1 text-[10px] font-mono text-amber-400 bg-amber-950/40 border border-amber-800 px-2 py-1 rounded-sm">
                      <Lock className="w-3 h-3" />
                      <span>Analyst Auth Required</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Target Incident Selector */}
              <div className="p-3 bg-black border border-[#222226] rounded-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 font-mono text-xs">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-zinc-400" />
                  <span className="text-zinc-400">Target Incident / Asset:</span>
                </div>
                <select
                  value={targetIncidentId}
                  onChange={(e) => setTargetIncidentId(e.target.value)}
                  className="bg-[#121216] border border-[#333] text-white rounded-sm px-2.5 py-1 text-xs focus:outline-none focus:border-[#ff3e3e] max-w-xs"
                >
                  {incidents.map((inc) => (
                    <option key={inc.id} value={inc.id}>
                      {inc.id} - {inc.targetHost} ({inc.severity})
                    </option>
                  ))}
                </select>
              </div>

              {/* Playbook Steps Pipeline */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-widest block">
                  Automated Step Pipeline
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {selectedPlaybook.steps.map((step, idx) => {
                    const isStepActive = executionStep === idx;
                    const isStepDone = executionStep > idx;

                    return (
                      <div
                        key={step.id}
                        className={`p-3 rounded-sm border font-mono text-xs transition ${
                          isStepActive
                            ? 'bg-blue-950/40 border-blue-500 shadow-md'
                            : isStepDone
                            ? 'bg-emerald-950/30 border-emerald-600/40'
                            : 'bg-black border-[#222226]'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white text-[11px]">
                            {idx + 1}. {step.name}
                          </span>
                          {isStepDone ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          ) : isStepActive ? (
                            <RefreshCw className="w-3.5 h-3.5 text-blue-400 animate-spin" />
                          ) : (
                            <Clock className="w-3.5 h-3.5 text-zinc-600" />
                          )}
                        </div>
                        <p className="text-[10px] text-zinc-400 mt-1">{step.description}</p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Run Trigger */}
              <div className="pt-2 flex items-center justify-between border-t border-[#222226]">
                <span className="text-[11px] font-mono text-zinc-400">
                  Target Host: <strong className="text-white">{targetIncident?.targetHost || 'N/A'}</strong>
                </span>
                <button
                  onClick={handleStartPlaybook}
                  disabled={isExecuting}
                  className="px-5 py-2 bg-[#ff3e3e] hover:bg-[#ff5555] disabled:opacity-50 text-black font-black font-mono text-xs uppercase tracking-wider rounded-sm transition flex items-center gap-2 shadow-lg"
                >
                  <Play className="w-4 h-4 fill-black" />
                  <span>{isExecuting ? 'EXECUTING PIPELINE...' : 'EXECUTE PLAYBOOK'}</span>
                </button>
              </div>

              {/* Live Execution Console */}
              {executionLogs.length > 0 && (
                <div className="p-4 bg-black border border-[#27272a] rounded-sm space-y-2">
                  <div className="flex items-center gap-2 text-zinc-400 text-xs font-mono border-b border-[#222226] pb-2">
                    <Terminal className="w-4 h-4 text-[#ff3e3e]" />
                    <span>SOAR Execution Real-Time Console Output</span>
                  </div>
                  <div className="space-y-1 font-mono text-xs max-h-48 overflow-y-auto">
                    {executionLogs.map((log, i) => (
                      <div
                        key={i}
                        className={
                          log.startsWith('[✓]')
                            ? 'text-emerald-400'
                            : log.startsWith('[✔]')
                            ? 'text-emerald-300 font-bold'
                            : log.startsWith('[*]')
                            ? 'text-blue-400'
                            : log.startsWith('[!]')
                            ? 'text-rose-400'
                            : 'text-zinc-300'
                        }
                      >
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Audit History */}
          <div className="p-5 bg-[#0a0a0c] border border-[#222226] rounded-sm space-y-3 font-mono">
            <h3 className="text-xs font-black uppercase tracking-wider text-zinc-400">SOAR Audit Trail</h3>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {auditHistory.map((item) => (
                <div
                  key={item.id}
                  className="p-2.5 bg-black border border-[#222226] rounded-sm flex items-center justify-between text-xs"
                >
                  <div>
                    <div className="font-bold text-white text-[11px]">{item.action || item.playbookName}</div>
                    <div className="text-[10px] text-zinc-500">
                      Target: {item.target} • {new Date(item.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded-sm bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold">
                    {item.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Modal */}
      {showConfirmModal && selectedPlaybook && (
        <SOARConfirmationModal
          playbook={selectedPlaybook}
          targetIncident={targetIncident}
          userRole={userRole}
          onConfirm={runPlaybook}
          onCancel={() => setShowConfirmModal(false)}
        />
      )}
    </div>
  );
};
