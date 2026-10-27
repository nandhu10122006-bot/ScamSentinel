export type RiskClassification = 
  | 'KNOWN THREAT DETECTED'
  | 'SUSPICIOUS'
  | 'NO KNOWN THREAT DETECTED'
  | 'UNABLE TO VERIFY';

export type IndicatorSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface DetectedIndicator {
  id: string;
  category: string;
  indicator: string;
  severity: IndicatorSeverity;
  score_impact: number;
  description: string;
}

export interface ThreatIntelResult {
  provider: string;
  configured: boolean;
  checked: boolean;
  status: string;
  threat_types: string[];
  summary: string;
}

export interface UrlBreakdown {
  scheme: string;
  domain: string;
  subdomain: string;
  tld: string;
  port?: number | null;
  path: string;
  query_params_count: number;
  is_ip_address: boolean;
  has_punycode: boolean;
  entropy: number;
}

export interface ScanResponse {
  target: string;
  normalized_url: string;
  hostname: string;
  is_url: boolean;
  classification: RiskClassification;
  risk_score: number;
  detected_indicators: DetectedIndicator[];
  explanation: string;
  scan_method: string;
  threat_intelligence: ThreatIntelResult;
  breakdown?: UrlBreakdown | null;
  timestamp: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  threat_intelligence_configured: boolean;
  configured_providers: string[];
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

class ScanService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = API_BASE_URL.replace(/\/+$/, '');
  }

  async checkHealth(): Promise<HealthResponse> {
    const response = await fetch(`${this.baseUrl}/api/health`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Health check failed with status: ${response.status}`);
    }

    return response.json();
  }

  async scanUrl(url: string): Promise<ScanResponse> {
    const trimmed = url.trim();
    if (!trimmed) {
      throw new Error('Please enter a valid URL to analyze.');
    }

    const response = await fetch(`${this.baseUrl}/api/scan/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ url: trimmed }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => null);
      const detail = errData?.detail || `Server returned error (${response.status})`;
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }

    return response.json();
  }

  async scanQr(qrContent: string): Promise<ScanResponse> {
    const trimmed = qrContent.trim();
    if (!trimmed) {
      throw new Error('Decoded QR code content is empty.');
    }

    const response = await fetch(`${this.baseUrl}/api/scan/qr`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ qr_content: trimmed }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => null);
      const detail = errData?.detail || `Server returned error (${response.status})`;
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }

    return response.json();
  }
}

export const scanService = new ScanService();
