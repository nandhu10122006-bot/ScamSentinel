# TrustLens AI 🛡️

**TrustLens AI** is an intelligent, full-stack predictive scam and threat intelligence platform designed to inspect URLs and physical/digital QR codes *before* users navigate to them.

Built with **FastAPI** (Python) and **React + TypeScript + Vite**, TrustLens AI evaluates destinations using local heuristic telemetry, Shannon entropy analysis, brand impersonation detection, and integration with **Google's Web Risk Lookup API**.

---

## 📁 Project Structure

TrustLens AI strictly enforces separation of concerns across its frontend and backend tiers:

```text
TrustLens-AI/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── LinkScanner.tsx      # URL inspection input, presets, and Check Link trigger
│   │   │   ├── QRScanner.tsx        # File drag-and-drop & live webcam QR code decoding
│   │   │   └── ScanResult.tsx       # Security card, risk score gauge, and indicators
│   │   ├── services/
│   │   │   └── scanService.ts       # Type-safe API client communicating with backend
│   │   ├── App.tsx                  # Single-page application root with tabs and history
│   │   ├── main.tsx                 # React DOM mount
│   │   └── index.css                # Tailwind CSS styling and theme definitions
│   ├── public/                      # Static assets and favicon
│   ├── package.json                 # Frontend dependencies and build scripts
│   └── .env.example                 # Example frontend environment configuration
│
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI application entry point with CORS
│   │   ├── routes/
│   │   │   └── scan.py              # /api/scan/url, /api/scan/qr, /api/health
│   │   ├── services/
│   │   │   ├── url_analyzer.py      # Unified multi-factor local heuristics engine
│   │   │   └── threat_intelligence.py # Google Web Risk Lookup API integration
│   │   └── schemas/
│   │       └── scan.py              # Pydantic v2 validation and response models
│   ├── tests/
│   │   └── test_scan.py             # Pytest unit and integration test suite
│   ├── requirements.txt             # Python backend dependencies
│   └── .env.example                 # Example backend environment configuration
│
├── .gitignore                       # Git ignore rules for virtualenvs, node_modules, secrets
└── README.md                        # Documentation and startup guides
```

---

## 🔒 Security Principles & Honest Classifications

1. **Client-Side QR Code Extraction:** Uploaded images and live webcam streams are decoded client-side inside the browser using HTML5 Canvas and `jsQR`. Destinations are extracted without opening or redirecting the user.
2. **Safe Telemetry & Zero Unrestricted Server Requests:** The backend does **not** execute arbitrary scripts or fetch arbitrary submitted payloads, protecting against SSRF and unauthorized client-side redirects.
3. **Honest Security Classifications:** Every scan returns one of four explicit classifications:
   - **`KNOWN THREAT DETECTED`**: A configured, trusted threat-intelligence service (e.g. Google Web Risk) confirms a threat match.
   - **`SUSPICIOUS`**: Local checks identify warning signs (e.g. brand spoofing, direct IP host, dangerous executable extension), but a confirmed threat has not been established.
   - **`NO KNOWN THREAT DETECTED`**: The available checks found no known threat. Note: This indicates the absence of known threats in evaluated sources, **not** a guarantee that the URL is safe.
   - **`UNABLE TO VERIFY`**: Verification could not be completed or the input is a non-URL payload (e.g. plain text notes).
4. **Separation of Heuristic Estimates:** Local heuristic risk scores ($0 - 100$) are estimates of structural anomaly, never described as mathematical probabilities of malice.
5. **Credential Isolation:** Frontend contains zero private API keys. `GOOGLE_WEB_RISK_API_KEY` remains strictly in backend environment variables.

---

## 🚀 Quick Start Guide

### 1. Backend Setup & Startup

1. Open a terminal and navigate to `backend`:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **macOS / Linux:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. Install required backend packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   *(Optional)* Add your Google Web Risk API key in `backend/.env`:
   ```env
   GOOGLE_WEB_RISK_API_KEY=your_google_cloud_api_key_here
   ```
   *If omitted, TrustLens AI will honestly report that live threat intelligence is unconfigured and provide complete local heuristic findings.*

5. Start the FastAPI backend server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   - API Base URL: `http://127.0.0.1:8000`
   - API Docs (Swagger): `http://127.0.0.1:8000/docs`
   - Health Check: `http://127.0.0.1:8000/api/health`

6. Run the automated backend test suite:
   ```bash
   pytest tests -v
   ```

---

### 2. Frontend Setup & Startup

1. Open a separate terminal and navigate to `frontend`:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   *(Defaults to `VITE_API_BASE_URL=http://localhost:8000`)*

4. Start the frontend development server:
   ```bash
   npm run dev
   ```
   - Access TrustLens AI in your browser at `http://localhost:5173`.

5. Build for production:
   ```bash
   npm run build
   ```

---

## 📡 API Reference

### 1. Health Status
- **Endpoint:** `GET /api/health`
- **Response:**
  ```json
  {
    "status": "healthy",
    "version": "1.0.0",
    "threat_intelligence_configured": false,
    "configured_providers": []
  }
  ```

---

### 2. URL Threat Scan
- **Endpoint:** `POST /api/scan/url`
- **Request Body:**
  ```json
  {
    "url": "http://paypal.com.account-update.verify-billing.attacker.xyz/login.php"
  }
  ```
- **Response:**
  ```json
  {
    "target": "http://paypal.com.account-update.verify-billing.attacker.xyz/login.php",
    "normalized_url": "http://paypal.com.account-update.verify-billing.attacker.xyz/login.php",
    "hostname": "paypal.com.account-update.verify-billing.attacker.xyz",
    "is_url": true,
    "classification": "SUSPICIOUS",
    "risk_score": 100,
    "detected_indicators": [
      {
        "id": "brand-spoof-paypal",
        "category": "reputation",
        "indicator": "Brand Mention in Subdomain/Path (Paypal)",
        "severity": "critical",
        "score_impact": 45,
        "description": "Mentions 'Paypal' in subdomain or path, but registered domain is 'attacker.xyz'."
      }
    ],
    "explanation": "Local checks identified 5 warning sign(s) for attacker.xyz (including Brand Mention in Subdomain/Path (Paypal)). A confirmed threat has not been established by external threat intelligence, but the URL exhibits suspicious characteristics. Live threat intelligence verification was unavailable (GOOGLE_WEB_RISK_API_KEY not configured).",
    "scan_method": "heuristics_only",
    "threat_intelligence": {
      "provider": "Google Web Risk Lookup API",
      "configured": false,
      "checked": false,
      "status": "not_configured",
      "threat_types": [],
      "summary": "Live threat intelligence verification unavailable. GOOGLE_WEB_RISK_API_KEY is not configured in backend environment."
    },
    "breakdown": {
      "scheme": "http",
      "domain": "attacker.xyz",
      "subdomain": "paypal.com.account-update.verify-billing",
      "tld": "xyz",
      "port": null,
      "path": "/login.php",
      "query_params_count": 0,
      "is_ip_address": false,
      "has_punycode": false,
      "entropy": 3.12
    },
    "timestamp": "2026-10-27T17:15:00Z"
  }
  ```

---

### 3. QR Content Scan
- **Endpoint:** `POST /api/scan/qr`
- **Request Body:**
  ```json
  {
    "qr_content": "https://bit.ly/secure-banking-token"
  }
  ```
- **Response:** Shared `ScanResponse` schema. If a plain text payload is provided, returns `UNABLE TO VERIFY` and clarifies that URL reputation checking cannot be applied to non-URL payloads.

---

## 📊 Summary of Capabilities & Limitations

| Capability | Status | Description |
| :--- | :--- | :--- |
| **URL Input & Check Link** | ✅ Functional | Validates, normalizes, inspects structural heuristics, queries Web Risk if configured, and displays results. |
| **QR Image Upload** | ✅ Functional | Client-side decoding using `jsQR` via Canvas without sending images or opening targets. |
| **QR Webcam Scanning** | ✅ Functional | Continuous camera feed scanning with viewfinder overlay and instant destination analysis. |
| **Local Heuristics Engine** | ✅ Functional | 15+ vectors: brand spoofing, direct IP hosts, dangerous extensions (`.exe`), high-risk TLDs, entropy, Punycode/IDN, shorteners. |
| **Google Web Risk Integration** | ✅ Functional | Queries `https://webrisk.googleapis.com/v1/uris:search` with `MALWARE`, `SOCIAL_ENGINEERING`, and `UNWANTED_SOFTWARE`. |
| **Honest Classifications** | ✅ Functional | Enforces `KNOWN THREAT DETECTED`, `SUSPICIOUS`, `NO KNOWN THREAT DETECTED`, and `UNABLE TO VERIFY`. |
| **Requires API Key** | ℹ️ Optional | Live Google Web Risk lookup requires a free Google Cloud API key (`GOOGLE_WEB_RISK_API_KEY`). Local heuristics operate 100% offline without any key. |
| **Limitation** | ⚠️ Note | Plain text QR codes cannot be evaluated for domain reputation and return `UNABLE TO VERIFY`. |
