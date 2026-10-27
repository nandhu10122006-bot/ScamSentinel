import React, { useState } from 'react';
import { Shield, Globe, QrCode, AlertCircle, History } from 'lucide-react';
import { LinkScanner } from './components/LinkScanner';
import { QRScanner } from './components/QRScanner';
import { ScanResult } from './components/ScanResult';
import { scanService, ScanResponse } from './services/scanService';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'url' | 'qr'>('url');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [currentResult, setCurrentResult] = useState<ScanResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanResponse[]>([]);

  const handleScanUrl = async (url: string) => {
    if (isLoading) return;
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const response = await scanService.scanUrl(url);
      setCurrentResult(response);
      setScanHistory((prev) => [response, ...prev.slice(0, 9)]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan failed. Please check backend service.';
      setErrorMessage(msg);
      setCurrentResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleScanQr = async (content: string) => {
    if (isLoading) return;
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const response = await scanService.scanQr(content);
      setCurrentResult(response);
      setScanHistory((prev) => [response, ...prev.slice(0, 9)]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'QR scan failed. Please check backend service.';
      setErrorMessage(msg);
      setCurrentResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Top Header - Project Name Only */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-5 h-5 text-black" />
            </div>
            <span className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-white via-slate-100 to-cyan-300 bg-clip-text text-transparent">
              TrustLens AI
            </span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-4xl mx-auto w-full px-4 py-8 space-y-6">
        {/* Tab Controls */}
        <div className="flex items-center justify-center">
          <div className="bg-slate-900/90 p-1.5 rounded-2xl border border-slate-800 flex items-center gap-2 shadow-xl">
            <button
              type="button"
              onClick={() => setActiveTab('url')}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
                activeTab === 'url'
                  ? 'bg-cyan-500 text-black shadow-lg shadow-cyan-500/25'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>Link Scanner</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('qr')}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
                activeTab === 'qr'
                  ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/25'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <QrCode className="w-4 h-4" />
              <span>QR Scanner</span>
            </button>
          </div>
        </div>

        {/* Active Tool Section */}
        <section className="space-y-6">
          {activeTab === 'url' ? (
            <LinkScanner onScan={handleScanUrl} isLoading={isLoading} />
          ) : (
            <QRScanner onScan={handleScanQr} isLoading={isLoading} />
          )}

          {/* Loading Animation */}
          {isLoading && (
            <div className="w-full bg-slate-900/60 border border-slate-800 rounded-2xl p-8 flex flex-col items-center justify-center text-center gap-3 animate-pulse">
              <div className="w-10 h-10 rounded-full border-3 border-cyan-500/20 border-t-cyan-400 animate-spin" />
              <p className="text-sm font-medium text-slate-300">Scanning...</p>
            </div>
          )}

          {/* Error Message */}
          {errorMessage && !isLoading && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p className="font-semibold text-white">Error</p>
                <p className="text-xs text-rose-300 leading-relaxed">{errorMessage}</p>
              </div>
            </div>
          )}

          {/* Result Card */}
          {currentResult && !isLoading && (
            <ScanResult result={currentResult} />
          )}
        </section>

        {/* Scan History */}
        {scanHistory.length > 1 && (
          <section className="pt-4 border-t border-slate-800/80">
            <div className="flex items-center gap-2 mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <History className="w-4 h-4 text-cyan-400" />
              <span>History</span>
            </div>
            <div className="space-y-2">
              {scanHistory.map((item, idx) => (
                <div
                  key={idx}
                  onClick={() => setCurrentResult(item)}
                  className="p-3 bg-slate-900/50 hover:bg-slate-900 border border-slate-800/80 rounded-xl flex items-center justify-between gap-3 cursor-pointer transition-colors"
                >
                  <div className="flex items-center gap-3 overflow-hidden">
                    <span
                      className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
                        item.classification === 'NO KNOWN THREAT DETECTED'
                          ? 'bg-emerald-400'
                          : item.classification === 'SUSPICIOUS'
                          ? 'bg-amber-400'
                          : item.classification === 'KNOWN THREAT DETECTED'
                          ? 'bg-rose-500'
                          : 'bg-slate-400'
                      }`}
                    />
                    <span className="text-xs font-mono text-slate-300 truncate">
                      {item.normalized_url || item.target}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-xs font-bold font-mono text-slate-400">
                      Score: {item.risk_score}
                    </span>
                    <span
                      className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                        item.classification === 'NO KNOWN THREAT DETECTED'
                          ? 'border-emerald-500/30 text-emerald-400'
                          : item.classification === 'SUSPICIOUS'
                          ? 'border-amber-500/30 text-amber-400'
                          : item.classification === 'KNOWN THREAT DETECTED'
                          ? 'border-rose-500/30 text-rose-400'
                          : 'border-slate-500/30 text-slate-400'
                      }`}
                    >
                      {item.classification}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}
      </main>

      {/* Clean Minimal Footer */}
      <footer className="py-6 text-center text-xs text-slate-600 mt-auto">
        TrustLens AI
      </footer>
    </div>
  );
};

export default App;
