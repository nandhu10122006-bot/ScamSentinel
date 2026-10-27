import React, { useState } from 'react';
import { Globe, ArrowRight, Clipboard, Trash2, Sparkles, AlertCircle } from 'lucide-react';

interface LinkScannerProps {
  onScan: (url: string) => Promise<void>;
  isLoading: boolean;
}

const PRESET_SAMPLES = [
  {
    label: 'Standard URL',
    url: 'https://en.wikipedia.org/wiki/Computer_security',
    tag: 'Standard',
    color: 'border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10',
  },
  {
    label: 'Phishing Brand Spoof',
    url: 'http://paypal.com.verify-account.attacker-hub.top/login.php',
    tag: 'Phishing',
    color: 'border-rose-500/30 text-rose-400 hover:bg-rose-500/10',
  },
  {
    label: 'IP & Executable',
    url: 'http://192.168.1.100:8080/system-update.exe',
    tag: 'Malware',
    color: 'border-red-500/30 text-red-400 hover:bg-red-500/10',
  },
  {
    label: 'Obfuscated Shortener',
    url: 'https://bit.ly/secure-banking-login-381',
    tag: 'Shortener',
    color: 'border-amber-500/30 text-amber-400 hover:bg-amber-500/10',
  },
];

export const LinkScanner: React.FC<LinkScannerProps> = ({ onScan, isLoading }) => {
  const [url, setUrl] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (isLoading) return; // Prevent duplicate submission

    setValidationError(null);

    const trimmed = url.trim();
    if (!trimmed) {
      setValidationError('Please enter a website URL or domain name to analyze.');
      return;
    }

    onScan(trimmed);
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrl(text.trim());
        setValidationError(null);
      }
    } catch {
      // Clipboard access might be blocked by browser permission
    }
  };

  const handleClear = () => {
    setUrl('');
    setValidationError(null);
  };

  const handleSelectPreset = (sampleUrl: string) => {
    if (isLoading) return;
    setUrl(sampleUrl);
    setValidationError(null);
    onScan(sampleUrl);
  };

  return (
    <div className="w-full bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex items-center gap-3 mb-4">
        <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
          <Globe className="w-5 h-5" />
        </div>
        <h2 className="text-base font-semibold text-white">URL Scanner</h2>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative flex items-center">
          <div className="absolute left-4 text-slate-500 pointer-events-none">
            <Globe className="w-5 h-5" />
          </div>

          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              if (validationError) setValidationError(null);
            }}
            placeholder="Enter or paste destination URL (e.g., https://example.com)..."
            disabled={isLoading}
            className="w-full pl-12 pr-36 py-3.5 bg-slate-950/90 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 transition-all font-mono text-sm disabled:opacity-60"
          />

          <div className="absolute right-3 flex items-center gap-1.5">
            {url && (
              <button
                type="button"
                onClick={handleClear}
                title="Clear input"
                disabled={isLoading}
                className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}

            <button
              type="button"
              onClick={handlePaste}
              title="Paste from clipboard"
              disabled={isLoading}
              className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <Clipboard className="w-4 h-4" />
            </button>

            <button
              type="submit"
              disabled={isLoading || !url.trim()}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-semibold text-xs uppercase tracking-wider rounded-lg transition-all shadow-md hover:shadow-cyan-500/25 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isLoading ? (
                <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
              ) : (
                <>
                  <span>Check Link</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </div>

        {validationError && (
          <div className="flex items-center gap-2 text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 px-3 py-2 rounded-lg">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{validationError}</span>
          </div>
        )}

        {/* Quick Test Samples */}
        <div className="pt-2 border-t border-slate-800/80">
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Test links:</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {PRESET_SAMPLES.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectPreset(sample.url)}
                disabled={isLoading}
                className={`text-xs px-3 py-1.5 rounded-lg border bg-slate-950/60 transition-all font-mono flex items-center gap-2 ${sample.color} disabled:opacity-50`}
              >
                <span className="font-sans font-medium">{sample.label}</span>
                <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-800/80">
                  {sample.tag}
                </span>
              </button>
            ))}
          </div>
        </div>
      </form>
    </div>
  );
};
