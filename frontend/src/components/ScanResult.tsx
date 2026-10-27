import React from 'react';
import { 
  ShieldCheck, 
  ShieldX, 
  AlertTriangle, 
  Copy, 
  Check, 
  Network, 
  Cpu, 
  Activity,
  Lock,
  Unlock,
  Layers,
  HelpCircle,
  Radio
} from 'lucide-react';
import { ScanResponse, IndicatorSeverity } from '../services/scanService';

interface ScanResultProps {
  result: ScanResponse;
}

export const ScanResult: React.FC<ScanResultProps> = ({ result }) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopyTarget = () => {
    navigator.clipboard.writeText(result.normalized_url || result.target);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getClassificationMeta = () => {
    switch (result.classification) {
      case 'KNOWN THREAT DETECTED':
        return {
          title: 'Known Threat Detected',
          badgeClass: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          gaugeColor: '#f43f5e',
          bgGlow: 'glow-rose',
          icon: <ShieldX className="w-8 h-8 text-rose-400" />,
          advice: 'A configured threat intelligence service confirmed this destination as a known threat. Do not visit.',
        };
      case 'SUSPICIOUS':
        return {
          title: 'Suspicious Destination',
          badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          gaugeColor: '#f59e0b',
          bgGlow: 'glow-amber',
          icon: <AlertTriangle className="w-8 h-8 text-amber-400" />,
          advice: 'Local heuristic checks identified warning signs. Proceed with caution.',
        };
      case 'NO KNOWN THREAT DETECTED':
        return {
          title: 'No Known Threat Detected',
          badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          gaugeColor: '#10b981',
          bgGlow: 'glow-emerald',
          icon: <ShieldCheck className="w-8 h-8 text-emerald-400" />,
          advice: 'Available checks found no known threats in evaluated sources. This is not a guarantee that the URL is safe.',
        };
      case 'UNABLE TO VERIFY':
      default:
        return {
          title: 'Unable to Verify',
          badgeClass: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
          gaugeColor: '#64748b',
          bgGlow: '',
          icon: <HelpCircle className="w-8 h-8 text-slate-400" />,
          advice: 'Verification could not be completed or the input is a non-URL payload.',
        };
    }
  };

  const meta = getClassificationMeta();

  const getSeverityBadge = (severity: IndicatorSeverity) => {
    switch (severity) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-400 border border-rose-500/30">Critical</span>;
      case 'high':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-orange-500/20 text-orange-400 border border-orange-500/30">High</span>;
      case 'medium':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-400 border border-amber-500/30">Medium</span>;
      case 'low':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-500/20 text-blue-400 border border-blue-500/30">Low</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-500/20 text-slate-400 border border-slate-500/30">Info</span>;
    }
  };

  return (
    <div className={`w-full bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-2xl backdrop-blur-xl transition-all ${meta.bgGlow}`}>
      {/* Top Header Card */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-800">
        <div className="flex items-start gap-4">
          <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800 flex-shrink-0">
            {meta.icon}
          </div>
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${meta.badgeClass}`}>
                {result.classification}
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1.5">
                <Cpu className="w-3 h-3 text-cyan-400" />
                {result.scan_method === 'heuristics_and_threat_intel' ? 'Live Intel + Heuristics' : result.scan_method === 'heuristics_only' ? 'Local Heuristics Only' : 'Payload Review'}
              </span>
            </div>
            <h3 className="text-xl font-bold text-white tracking-tight">{meta.title}</h3>
            <p className="text-xs text-slate-400">{meta.advice}</p>
          </div>
        </div>

        {/* Circular Risk Score Gauge */}
        <div className="flex items-center gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800 self-start lg:self-auto min-w-[210px]">
          <div className="relative w-16 h-16 flex items-center justify-center flex-shrink-0">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-slate-800"
                strokeWidth="3.5"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                stroke={meta.gaugeColor}
                strokeWidth="3.5"
                strokeDasharray={`${result.risk_score}, 100`}
                strokeLinecap="round"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-base font-extrabold text-white font-mono leading-none">{result.risk_score}</span>
              <span className="text-[9px] text-slate-400 uppercase font-bold">/ 100</span>
            </div>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">Heuristic Index</p>
            <p className="text-sm font-bold text-white">
              {result.risk_score <= 25 ? 'Minimal Flags' : result.risk_score <= 60 ? 'Moderate Suspicion' : 'Elevated Hazard'}
            </p>
            <p className="text-[10px] text-slate-500">Heuristic score estimate, not probability</p>
          </div>
        </div>
      </div>

      {/* Target Link & Hostname Row */}
      <div className="my-5 p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0 overflow-hidden">
          {result.breakdown?.scheme === 'https' ? (
            <Lock className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          ) : (
            <Unlock className="w-4 h-4 text-amber-400 flex-shrink-0" />
          )}
          <div className="min-w-0 truncate">
            <span className="font-mono text-xs text-slate-300 block truncate">
              {result.normalized_url || result.target}
            </span>
            {result.hostname && (
              <span className="text-[11px] text-cyan-400 font-mono block">
                Hostname: {result.hostname}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-1.5 flex-shrink-0 self-end sm:self-auto">
          <button
            type="button"
            onClick={handleCopyTarget}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors flex items-center gap-1 text-xs"
            title="Copy URL"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span className="text-[11px] hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Threat Intelligence Status Box */}
      <div className="mb-5 p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3">
        <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mt-0.5 flex-shrink-0">
          <Radio className="w-4 h-4" />
        </div>
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-white">{result.threat_intelligence.provider}</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold ${
              result.threat_intelligence.status === 'confirmed_threat'
                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                : result.threat_intelligence.status === 'no_threat_found'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-slate-800 text-slate-400 border border-slate-700'
            }`}>
              {result.threat_intelligence.status === 'confirmed_threat'
                ? 'Threat Match'
                : result.threat_intelligence.status === 'no_threat_found'
                ? 'Lookup Clean'
                : result.threat_intelligence.status === 'not_configured'
                ? 'Unconfigured'
                : 'Lookup Unavailable'}
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            {result.threat_intelligence.summary}
          </p>
        </div>
      </div>

      {/* Explanation Banner */}
      <div className="mb-6 p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
        <div className="flex items-center gap-2 mb-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-400">
          <Activity className="w-3.5 h-3.5" />
          <span>Security Assessment Summary</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed font-sans">{result.explanation}</p>
      </div>

      {/* Technical Breakdown Grid */}
      {result.breakdown && (
        <div className="mb-6">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
            <Network className="w-3.5 h-3.5 text-cyan-400" />
            <span>Telemetry & Infrastructure Breakdown</span>
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5">
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">Domain</span>
              <span className="text-xs font-mono font-medium text-slate-200 truncate block">
                {result.breakdown.domain || 'N/A'}
              </span>
            </div>
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">TLD Extension</span>
              <span className="text-xs font-mono font-medium text-slate-200">
                {result.breakdown.tld ? `.${result.breakdown.tld}` : 'None'}
              </span>
            </div>
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">Subdomain</span>
              <span className="text-xs font-mono font-medium text-slate-200 truncate block">
                {result.breakdown.subdomain || 'None'}
              </span>
            </div>
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">Shannon Entropy</span>
              <span className="text-xs font-mono font-medium text-slate-200">
                {result.breakdown.entropy} {result.breakdown.entropy > 3.8 ? '⚠️' : '✓'}
              </span>
            </div>
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">Direct IP Host</span>
              <span className={`text-xs font-mono font-medium ${result.breakdown.is_ip_address ? 'text-rose-400' : 'text-slate-300'}`}>
                {result.breakdown.is_ip_address ? 'Detected (Yes)' : 'No (Domain)'}
              </span>
            </div>
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">Punycode / IDN</span>
              <span className={`text-xs font-mono font-medium ${result.breakdown.has_punycode ? 'text-amber-400' : 'text-slate-300'}`}>
                {result.breakdown.has_punycode ? 'Detected (Punycode)' : 'Clean'}
              </span>
            </div>
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">Query Params</span>
              <span className="text-xs font-mono font-medium text-slate-200">
                {result.breakdown.query_params_count} parameter(s)
              </span>
            </div>
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">Port</span>
              <span className="text-xs font-mono font-medium text-slate-200">
                {result.breakdown.port ? result.breakdown.port : result.breakdown.scheme === 'https' ? '443 (Default)' : '80 (Default)'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Detected Warning Signs & Indicators */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Detected Warning Indicators ({result.detected_indicators.length})</span>
          </div>
          <span className="text-[11px] font-mono text-slate-500 lowercase">
            heuristic risk accumulation
          </span>
        </h4>

        {result.detected_indicators.length === 0 ? (
          <div className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-3">
            <ShieldCheck className="w-5 h-5 flex-shrink-0" />
            <span>Zero warning flags detected by heuristic checks.</span>
          </div>
        ) : (
          <div className="space-y-2.5">
            {result.detected_indicators.map((ind, idx) => (
              <div
                key={ind.id || idx}
                className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-slate-700 transition-colors"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    {getSeverityBadge(ind.severity)}
                    <span className="text-xs font-bold text-white">{ind.indicator}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 uppercase">
                      {ind.category}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{ind.description}</p>
                </div>

                <div className="flex-shrink-0 self-end sm:self-center text-right font-mono text-xs font-semibold text-rose-400 bg-rose-500/10 px-2.5 py-1 rounded-lg border border-rose-500/20">
                  +{ind.score_impact} pts
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
