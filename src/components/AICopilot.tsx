import React, { useState } from 'react';
import { 
  Sparkles, 
  Send, 
  FileText, 
  Terminal, 
  ShieldCheck, 
  Copy, 
  Download, 
  RefreshCw, 
  User, 
  Bot, 
  Zap,
  HelpCircle
} from 'lucide-react';
import Markdown from 'react-markdown';
import { ChatMessage, SecurityIncident, ForensicArtifact } from '../types';
import { sendCopilotMessage, generateFullForensicReport } from '../services/api';

interface AICopilotProps {
  incidents: SecurityIncident[];
  artifacts: ForensicArtifact[];
  onTriggerPlaybook?: (playbookId: string) => void;
}

export const AICopilot: React.FC<AICopilotProps> = ({
  incidents,
  artifacts,
  onTriggerPlaybook,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'msg-1',
      role: 'assistant',
      content: `### SentinelX Threat Operations Co-Pilot Initialized
I am your AI Security Operations and Digital Forensics analyst powered by **Gemini 3.7 Flash**.

I have real-time access to the SIEM telemetry feed, active incident queue (${incidents.length} incidents), and forensic artifacts.

**How can I assist your investigation today?**
- Investigate active intrusion indicators (e.g. *ALPHV ransomware on SRV-PROD-DB01*)
- Reverse-engineer suspicious shellcode or obfuscated PowerShell scripts
- Generate YARA / Sigma detection signatures
- Draft comprehensive CISO Executive & Technical Post-Mortem Reports`,
      timestamp: 'Just now',
    },
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [selectedIncidentForReport, setSelectedIncidentForReport] = useState<string>(incidents[0]?.id || '');
  const [generatedReport, setGeneratedReport] = useState<string | null>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  const quickPrompts = [
    'Analyze blast radius for INC-9041 (ALPHV Ransomware)',
    'Generate YARA rule for reflective DLL injection',
    'Explain AMSI memory bypass technique in mimic PowerShell',
    'Recommend firewall blocking commands for active C2 nodes'
  ];

  const handleSendMessage = async (textToSend?: string) => {
    const text = textToSend || inputQuery;
    if (!text.trim() || isLoading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString(),
    };

    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInputQuery('');
    setIsLoading(true);

    try {
      const contextData = {
        activeIncidentsCount: incidents.length,
        criticalIncidents: incidents.filter((i) => i.severity === 'CRITICAL').map((i) => ({ id: i.id, title: i.title, host: i.targetHost, sourceIp: i.sourceIp })),
        activeArtifacts: artifacts.map((a) => a.name),
      };

      const res = await sendCopilotMessage(newMessages, contextData);
      if (res.success && res.reply) {
        const assistantMsg: ChatMessage = {
          id: `asst-${Date.now()}`,
          role: 'assistant',
          content: res.reply,
          timestamp: new Date().toLocaleTimeString(),
          suggestedActions: res.suggestedActions,
        };
        setMessages([...newMessages, assistantMsg]);
      }
    } catch (err) {
      console.error('Copilot error:', err);
      const errMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content: `⚠️ Error querying SentinelX AI: ${(err as Error).message}. Operating with local DFIR intelligence rules.`,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages([...newMessages, errMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    const targetInc = incidents.find((i) => i.id === selectedIncidentForReport) || incidents[0];
    if (!targetInc || isGeneratingReport) return;

    try {
      setIsGeneratingReport(true);
      const res = await generateFullForensicReport(targetInc, artifacts);
      if (res.success && res.markdown) {
        setGeneratedReport(res.markdown);
      }
    } catch (err) {
      console.error('Report error:', err);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const copyReport = () => {
    if (!generatedReport) return;
    navigator.clipboard.writeText(generatedReport);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const downloadReport = () => {
    if (!generatedReport) return;
    const blob = new Blob([generatedReport], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SentinelX_DFIR_Report_${selectedIncidentForReport}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 pb-12 font-mono">
      {/* Top Banner */}
      <div className="p-5 bg-[#0a0a0c] border border-[#222226] rounded-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-sm bg-[#ff3e3e]/10 text-[#ff3e3e] border border-[#ff3e3e]/30">
              <Sparkles className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-black text-white uppercase tracking-wider">SecOps AI Threat Analyst Co-Pilot & DFIR Synthesizer</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1 max-w-2xl font-sans leading-relaxed">
            Conversational cybersecurity AI for deep threat investigation, root-cause reconstruction, memory artifact reverse-engineering, and one-click incident post-mortem generation.
          </p>
        </div>
      </div>

      {/* Main Split Layout: Left Chat, Right Incident Post-Mortem Report Generator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* AI Threat Analyst Chat (Left 7 cols) */}
        <div className="lg:col-span-7 bg-[#0a0a0c] border border-[#222226] rounded-sm flex flex-col h-[700px] shadow-2xl overflow-hidden">
          {/* Chat Header */}
          <div className="px-5 py-3.5 bg-[#050505] border-b border-[#222226] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bot className="w-4 h-4 text-[#ff3e3e]" />
              <h3 className="text-xs font-black text-white uppercase tracking-wider">SentinelX Threat Analyst Chat</h3>
            </div>
            <span className="text-[10px] text-blue-400 font-mono px-2 py-0.5 rounded-sm bg-[#18181b] border border-[#333] uppercase font-bold">
              Gemini Active
            </span>
          </div>

          {/* Chat Messages Stream */}
          <div className="flex-1 p-5 overflow-y-auto space-y-4 text-xs">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role !== 'user' && (
                  <div className="w-7 h-7 rounded-sm bg-[#150a0b] border border-[#ff3e3e]/30 flex items-center justify-center text-[#ff3e3e] shrink-0 mt-0.5">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div
                  className={`p-3.5 rounded-sm max-w-[88%] leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-[#ff3e3e] text-black font-semibold'
                      : 'bg-[#050505] border border-[#222226] text-zinc-200 shadow-md'
                  }`}
                >
                  <div className="markdown-body prose prose-invert prose-xs max-w-none font-sans">
                    <Markdown>{msg.content}</Markdown>
                  </div>

                  {msg.suggestedActions && msg.suggestedActions.length > 0 && (
                    <div className="mt-3 pt-2.5 border-t border-[#222226] flex flex-wrap gap-1.5 font-mono">
                      {msg.suggestedActions.map((act, i) => (
                        <button
                          key={i}
                          onClick={() => {
                            if (act.actionType === 'TRIGGER_PLAYBOOK' && onTriggerPlaybook) {
                              onTriggerPlaybook(act.payload?.playbookId || 'pb-isolate-host');
                            } else {
                              handleSendMessage(act.label);
                            }
                          }}
                          className="px-2.5 py-1 rounded-sm bg-[#18181b] hover:bg-[#27272a] text-blue-400 border border-[#333] text-[10px] font-bold uppercase transition flex items-center gap-1"
                        >
                          <Zap className="w-3 h-3 text-amber-400" />
                          <span>{act.label}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {msg.role === 'user' && (
                  <div className="w-7 h-7 rounded-sm bg-[#ff3e3e] flex items-center justify-center text-black font-bold shrink-0 mt-0.5">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}

            {isLoading && (
              <div className="flex gap-3 items-center text-zinc-400 text-xs">
                <div className="w-7 h-7 rounded-sm bg-[#150a0b] border border-[#ff3e3e]/30 flex items-center justify-center text-[#ff3e3e] shrink-0">
                  <Sparkles className="w-4 h-4 animate-spin" />
                </div>
                <div className="p-3 bg-[#050505] border border-[#222226] rounded-sm text-blue-400 flex items-center gap-2 font-mono text-[11px]">
                  <span className="w-2 h-2 rounded-full bg-blue-400 animate-ping"></span>
                  <span>Analyzing telemetry & reverse-engineering indicators with Gemini...</span>
                </div>
              </div>
            )}
          </div>

          {/* Quick Prompts */}
          <div className="px-4 py-2 bg-[#050505] border-t border-[#222226] flex gap-2 overflow-x-auto">
            {quickPrompts.map((qp, idx) => (
              <button
                key={idx}
                onClick={() => handleSendMessage(qp)}
                className="whitespace-nowrap px-2.5 py-1 rounded-sm bg-[#18181b] hover:bg-[#27272a] border border-[#333] text-[10px] text-zinc-300 transition uppercase font-bold"
              >
                {qp}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div className="p-3 bg-[#050505] border-t border-[#222226] flex items-center gap-2">
            <input
              type="text"
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
              placeholder="Ask AI Analyst: e.g. Analyze memory dump offset 0x7FFF, extract C2 IPs, or build Sigma rule..."
              className="flex-1 bg-[#0a0a0c] border border-[#333] rounded-sm px-4 py-2.5 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-[#ff3e3e] font-mono transition"
            />
            <button
              onClick={() => handleSendMessage()}
              disabled={isLoading || !inputQuery.trim()}
              className="p-2.5 rounded-sm bg-[#ff3e3e] hover:bg-[#ff5555] text-black font-black shadow transition disabled:opacity-50"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Forensic Report Generator (Right 5 cols) */}
        <div className="lg:col-span-5 bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-2xl flex flex-col justify-between space-y-4 h-[700px]">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#222226]">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-[#ff3e3e]" />
                <h3 className="text-xs font-black text-white uppercase tracking-wider">DFIR Post-Mortem Synthesizer</h3>
              </div>
            </div>

            {/* Target incident selector */}
            <div className="mt-3 space-y-2 text-xs">
              <label className="text-zinc-400 font-bold uppercase tracking-wider text-[10px]">
                Generate Executive Report For Incident
              </label>
              <select
                value={selectedIncidentForReport}
                onChange={(e) => setSelectedIncidentForReport(e.target.value)}
                className="w-full bg-[#050505] border border-[#333] rounded-sm p-2 text-white focus:outline-none focus:border-[#ff3e3e] font-mono text-xs uppercase"
              >
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    {inc.id} - {inc.title} ({inc.severity})
                  </option>
                ))}
              </select>

              <button
                onClick={handleGenerateReport}
                disabled={isGeneratingReport}
                className="w-full mt-2 py-2 rounded-sm bg-blue-600 hover:bg-blue-500 text-white font-black text-xs uppercase tracking-wider shadow transition flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <Sparkles className={`w-3.5 h-3.5 ${isGeneratingReport ? 'animate-spin' : ''}`} />
                <span>{isGeneratingReport ? 'Synthesizing Forensic Report...' : 'Generate Full Executive Report'}</span>
              </button>
            </div>

            {/* Report Preview */}
            <div className="mt-4 bg-[#050505] border border-[#222226] rounded-sm p-4 h-[440px] overflow-y-auto text-xs text-zinc-300 font-sans leading-relaxed">
              {!generatedReport ? (
                <div className="text-center py-16 text-zinc-500 space-y-2 font-mono text-xs">
                  <FileText className="w-8 h-8 mx-auto text-zinc-600" />
                  <p className="uppercase">Click Generate to synthesize a complete CISO-ready Incident Post-Mortem & Evidence Report.</p>
                </div>
              ) : (
                <div className="markdown-body prose prose-invert prose-xs max-w-none">
                  <Markdown>{generatedReport}</Markdown>
                </div>
              )}
            </div>
          </div>

          {/* Action buttons */}
          {generatedReport && (
            <div className="pt-2 border-t border-[#222226] flex items-center justify-between gap-2 uppercase font-mono text-xs">
              <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-bold">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Report Ready</span>
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={copyReport}
                  className="px-3 py-1.5 rounded-sm bg-[#18181b] hover:bg-[#27272a] text-zinc-200 text-[10px] font-bold border border-[#333] transition flex items-center gap-1"
                >
                  <Copy className="w-3 h-3" />
                  <span>{copiedReport ? 'Copied!' : 'Copy'}</span>
                </button>
                <button
                  onClick={downloadReport}
                  className="px-3 py-1.5 rounded-sm bg-[#ff3e3e] hover:bg-[#ff5555] text-black text-[10px] font-black transition flex items-center gap-1"
                >
                  <Download className="w-3 h-3" />
                  <span>Download .md</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
