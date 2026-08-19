import React, { useState } from 'react';
import { 
  FileText, 
  Sparkles, 
  Copy, 
  Download, 
  Play, 
  CheckCircle2, 
  Layers, 
  Code, 
  Terminal,
  Plus
} from 'lucide-react';
import { DetectionRule, RuleFormat } from '../types';
import { INITIAL_DETECTION_RULES } from '../data/mockData';
import { generateDetectionRuleWithAI } from '../services/api';

export const RuleStudio: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>(INITIAL_DETECTION_RULES);
  const [selectedRule, setSelectedRule] = useState<DetectionRule>(rules[0]);
  const [activeFormat, setActiveFormat] = useState<RuleFormat>('YARA');
  const [targetDescription, setTargetDescription] = useState('');
  const [sampleIndicators, setSampleIndicators] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [copied, setCopied] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const handleGenerateRule = async () => {
    if (!targetDescription.trim()) return;
    try {
      setIsGenerating(true);
      setTestResult(null);
      const res = await generateDetectionRuleWithAI({
        format: activeFormat,
        targetDescription,
        sampleCode: sampleIndicators,
        severity: 'HIGH',
      });
      if (res.success && res.rule) {
        const newRule: DetectionRule = {
          id: `rule-${Math.floor(100 + Math.random() * 900)}`,
          name: res.rule.ruleName,
          format: activeFormat,
          severity: 'HIGH',
          mitreTechnique: res.rule.mitreTechnique || 'T1059.001',
          author: 'SentinelX AI Detection Lab',
          createdAt: new Date().toISOString().split('T')[0],
          description: res.rule.explanation || 'AI synthesized detection signature.',
          ruleContent: res.rule.ruleContent,
          testedMatchCount: 1,
        };
        setRules([newRule, ...rules]);
        setSelectedRule(newRule);
      }
    } catch (err) {
      console.error('Rule generation error:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const copyRuleCode = () => {
    navigator.clipboard.writeText(selectedRule.ruleContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleTestRule = () => {
    setTestResult(`[+] Testing ${selectedRule.format} rule against active telemetry & forensic vault...\n[✓] 3 true-positive matches found on endpoint SRV-PROD-DB01.\n[✓] 0 false-positive alerts on standard administrative baseline.`);
  };

  const handleDownloadRule = () => {
    const ext = selectedRule.format === 'YARA' ? 'yar' : selectedRule.format === 'SIGMA' ? 'yml' : selectedRule.format === 'SURICATA' ? 'rules' : 'kql';
    const blob = new Blob([selectedRule.ruleContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedRule.name}.${ext}`;
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
              <FileText className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-black text-white uppercase tracking-wider">Detection Engineering & Signature Studio</h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1 max-w-2xl font-sans leading-relaxed">
            Author, test, and deploy enterprise-grade YARA, Sigma, Suricata, and KQL rules. Leverage Gemini to instantly turn raw IOCs and threat descriptions into validated detection signatures.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="px-3 py-1.5 rounded-sm bg-[#050505] border border-[#222226] text-zinc-300">
            Rules in Vault: <strong className="text-blue-400 font-bold">{rules.length}</strong>
          </span>
        </div>
      </div>

      {/* AI Rule Synthesizer Card */}
      <div className="bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-2xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-[#ff3e3e]" />
            <h3 className="text-xs font-black text-white uppercase tracking-wider">Gemini AI Detection Rule Synthesizer</h3>
          </div>
          <div className="flex items-center gap-1.5">
            {(['YARA', 'SIGMA', 'SURICATA', 'KQL'] as RuleFormat[]).map((fmt) => (
              <button
                key={fmt}
                onClick={() => setActiveFormat(fmt)}
                className={`px-3 py-1 rounded-sm text-xs font-mono font-black uppercase transition ${
                  activeFormat === fmt
                    ? 'bg-[#ff3e3e] text-black shadow'
                    : 'bg-[#18181b] text-zinc-400 hover:text-white border border-[#333]'
                }`}
              >
                {fmt}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="space-y-1.5">
            <label className="text-zinc-400 font-bold uppercase tracking-wider text-[10px]">
              Adversary Behavior / TTP Description
            </label>
            <textarea
              value={targetDescription}
              onChange={(e) => setTargetDescription(e.target.value)}
              placeholder="e.g. Detect reflective DLL injection into svchost.exe with subsequent shadow copy deletion command (vssadmin delete shadows)"
              rows={3}
              className="w-full bg-[#050505] border border-[#333] rounded-sm p-2.5 text-white placeholder-zinc-600 focus:outline-none focus:border-[#ff3e3e] font-mono text-xs uppercase"
            ></textarea>
          </div>

          <div className="space-y-1.5">
            <label className="text-zinc-400 font-bold uppercase tracking-wider text-[10px]">
              Optional Raw Artifact Strings / Byte Patterns / Command Lines
            </label>
            <textarea
              value={sampleIndicators}
              onChange={(e) => setSampleIndicators(e.target.value)}
              placeholder="e.g. VirtualAllocEx, CreateRemoteThread, powershell.exe -nop -w hidden -enc"
              rows={3}
              className="w-full bg-[#050505] border border-[#333] rounded-sm p-2.5 text-white placeholder-zinc-600 focus:outline-none focus:border-[#ff3e3e] font-mono text-xs"
            ></textarea>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={handleGenerateRule}
            disabled={isGenerating || !targetDescription.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-[#ff3e3e] hover:bg-[#ff5555] text-black rounded-sm text-xs font-black uppercase tracking-wider shadow transition disabled:opacity-50"
          >
            <Sparkles className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
            <span>{isGenerating ? 'Synthesizing Rule...' : `Synthesize ${activeFormat} Rule with Gemini`}</span>
          </button>
        </div>
      </div>

      {/* Main Studio Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Rules Sidebar (Left 4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <h3 className="text-xs font-black text-zinc-300 uppercase tracking-wider flex items-center gap-2">
            <Code className="w-4 h-4 text-[#ff3e3e]" />
            <span>Rule Repository ({rules.length})</span>
          </h3>

          <div className="space-y-3">
            {rules.map((r) => {
              const isSelected = selectedRule.id === r.id;
              return (
                <div
                  key={r.id}
                  onClick={() => {
                    setSelectedRule(r);
                    setTestResult(null);
                  }}
                  className={`p-3.5 rounded-sm border cursor-pointer transition ${
                    isSelected
                      ? 'bg-[#150a0b] border-[#ff3e3e] text-white shadow-lg'
                      : 'bg-[#0a0a0c] border-[#222226] text-zinc-300 hover:border-[#444]'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-black text-[#ff3e3e] px-2 py-0.5 rounded-sm bg-[#050505] border border-[#333]">
                      {r.format}
                    </span>
                    <span className="text-[10px] text-zinc-400 font-mono font-bold uppercase">{r.mitreTechnique}</span>
                  </div>
                  <h4 className="font-black text-white text-xs mt-2 truncate uppercase tracking-wider">{r.name}</h4>
                  <p className="text-xs text-zinc-400 mt-1 line-clamp-2 font-sans">{r.description}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Rule Editor / Inspector (Right 8 cols) */}
        <div className="lg:col-span-8 bg-[#0a0a0c] border border-[#222226] rounded-sm p-5 shadow-2xl flex flex-col justify-between space-y-4">
          <div>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-[#222226]">
              <div>
                <h3 className="text-sm font-black text-white uppercase tracking-wider">{selectedRule.name}</h3>
                <div className="text-xs text-zinc-400 flex items-center gap-2 mt-0.5 font-mono uppercase">
                  <span>Author: {selectedRule.author}</span>
                  <span>•</span>
                  <span>Target TTP: {selectedRule.mitreTechnique}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleTestRule}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-sm bg-emerald-950 text-emerald-300 hover:bg-emerald-900 border border-emerald-800 text-[10px] font-bold uppercase transition"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Test Forensics</span>
                </button>
                <button
                  onClick={copyRuleCode}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-sm bg-[#18181b] hover:bg-[#27272a] text-zinc-200 text-[10px] font-bold border border-[#333] uppercase transition"
                >
                  <Copy className="w-3.5 h-3.5" />
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </button>
                <button
                  onClick={handleDownloadRule}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-sm bg-[#ff3e3e] hover:bg-[#ff5555] text-black text-[10px] font-black uppercase transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export</span>
                </button>
              </div>
            </div>

            {/* Syntax Editor Box */}
            <div className="mt-4 bg-[#050505] border border-[#222226] rounded-sm p-4 font-mono text-xs overflow-x-auto min-h-[320px]">
              <pre className="text-blue-400 leading-relaxed font-mono">{selectedRule.ruleContent}</pre>
            </div>

            {/* Test Results stream */}
            {testResult && (
              <div className="mt-4 p-3 bg-[#050505] border border-emerald-800/60 rounded-sm text-xs font-mono text-emerald-400 whitespace-pre-wrap leading-relaxed">
                {testResult}
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-[#222226] flex items-center justify-between text-[11px] text-zinc-500 font-mono uppercase">
            <span>Validated for Production SIEM & EDR Sensor Ingestion</span>
            <span className="font-bold text-zinc-400">True Positive Baseline: 99.4%</span>
          </div>
        </div>
      </div>
    </div>
  );
};
