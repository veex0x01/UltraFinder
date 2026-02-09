<p align="center">
  <h1 align="center">🔍 UltraFinder</h1>
  <p align="center"><strong>Ultimate Web Reconnaissance Tool</strong></p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#features">Features</a> •
    <a href="#sponsor">Sponsor</a>
  </p>
</p>

---

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge" alt="Platform">
</p>

## 📖 Description

**UltraFinder** is a powerful Go-based web reconnaissance tool that combines the best features from multiple popular security tools:

| Tool | Features Integrated |
|------|---------------------|
| **GoSpider** | Fast async crawling, external sources integration |
| **Hakrawler** | Efficient endpoint discovery, form extraction |
| **LogParamFinder** | Sensitive parameter detection, debug code finding |
| **T-Recon** | Multi-tool reconnaissance approach |

Built for **bug bounty hunters**, **penetration testers**, and **security researchers** who need a comprehensive, all-in-one reconnaissance solution.

---

## ✨ Features

### 🚀 Core Features
- **Fast Async Web Crawling** - Powered by Colly with concurrent requests
- **JavaScript Endpoint Extraction** - LinkFinder-style URL extraction from JS files
- **Sensitive Parameter Discovery** - Detects API keys, tokens, debug flags in URLs
- **Hidden Form Field Detection** - Finds hidden inputs with sensitive names
- **Subdomain Discovery** - Extracts subdomains from response bodies
- **AWS S3 Bucket Detection** - Identifies exposed S3 buckets

### 🌐 External Sources
- **Wayback Machine** - Historical URL discovery
- **CommonCrawl** - Large-scale web crawl data
- **AlienVault OTX** - Threat intelligence URLs

### 🥷 Stealth Mode
- **Random User-Agent Rotation** - 20+ real browser user agents
- **Random Request Delays** - Configurable jitter to avoid rate limiting
- **Browser-like Headers** - Accept, Accept-Language, Sec-Fetch-* headers
- **Random Referer Headers** - Simulates traffic from search engines

### 🔬 Deep Analysis Mode
- **API Key Extraction** - AWS, GitHub, Slack, Stripe, JWT, private keys
- **AJAX/XHR Endpoint Parsing** - fetch, axios, jQuery, XMLHttpRequest
- **WAF/CDN Detection** - Cloudflare, AWS WAF, Akamai, Imperva, Sucuri
- **Backup File Discovery** - .bak, .backup, .old, .swp files
- **Source Map Parsing** - Extract original JS source files
- **Service Worker Analysis** - Detect service worker registrations

---

## 📦 Installation

### Prerequisites
- Go 1.21 or higher

### Build from Source

```bash
# Clone the repository
git clone https://github.com/veex0x01/ultrafinder.git
cd ultrafinder

# Download dependencies
go mod tidy

# Build the binary
go build -o ultrafinder .

# (Optional) Install globally
go install .
```

### Verify Installation

```bash
./ultrafinder --version
# UltraFinder v1.0.0 by veex0x01
```

---

## 🚀 Usage

### Basic Scan

```bash
./ultrafinder -u https://example.com
```

### 🔥 Ultimate Scan (All Features)

```bash
./ultrafinder -u https://example.com -d 3 -t 20 --stealth --deep --all-sources --subs -v -o results.txt
```

### Common Use Cases

```bash
# Quick reconnaissance
./ultrafinder -u https://target.com -d 2

# Deep scan with external sources
./ultrafinder -u https://target.com --deep --all-sources

# Stealthy scan (evade bot detection)
./ultrafinder -u https://target.com --stealth --deep

# Include subdomains
./ultrafinder -u https://target.com --subs --all-sources

# Save results to JSON
./ultrafinder -u https://target.com --deep -o results.json --json

# Use with proxy (Burp Suite)
./ultrafinder -u https://target.com -p http://127.0.0.1:8080

# Custom headers and cookies
./ultrafinder -u https://target.com -c "session=abc123" -H "Authorization: Bearer token"
```

---

## ⚙️ Options

### Target Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL **(required)** | - |

### Crawling Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --depth` | Maximum crawl depth | `2` |
| `-t, --threads` | Concurrent threads | `10` |
| `-m, --timeout` | Request timeout (seconds) | `30` |
| `-k, --delay` | Delay between requests (seconds) | `0` |
| `--random-delay` | Random delay jitter (milliseconds) | `0` |

### HTTP Options

| Flag | Description |
|------|-------------|
| `-p, --proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) |
| `-c, --cookie` | Cookie string (e.g., `session=abc`) |
| `-H, --header` | Custom header (can be used multiple times) |
| `-a, --user-agent` | Custom User-Agent string |
| `--no-redirect` | Disable following redirects |

### Stealth Options

| Flag | Description |
|------|-------------|
| `--stealth` | Enable full stealth mode (random UA, headers, delays) |
| `--random-ua` | Use random User-Agent per request |

### Deep Analysis Options

| Flag | Description |
|------|-------------|
| `--deep` | Enable deep analysis (API keys, backups, WAF) |

### Scope Options

| Flag | Description |
|------|-------------|
| `--subs` | Include subdomains in crawl scope |

### External Sources

| Flag | Description |
|------|-------------|
| `--wayback` | Fetch URLs from Wayback Machine |
| `--commoncrawl` | Fetch URLs from CommonCrawl |
| `--otx` | Fetch URLs from AlienVault OTX |
| `--all-sources` | Fetch from all external sources |

### Output Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output file path |
| `--json` | Output results as JSON |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress console output |

---

## 📊 Output Types

| Type | Description | Example |
|------|-------------|---------|
| `[href]` | HTML anchor links | `/admin/dashboard` |
| `[form]` | Form action URLs | `/api/login` |
| `[upload-form]` | File upload forms | `/upload` |
| `[js]` | JavaScript files | `/assets/app.js` |
| `[linkfinder]` | URLs extracted from JS | `/api/v2/users` |
| `[sensitive-param]` | Sensitive query parameters | `?debug=true` |
| `[hidden-field]` | Hidden form fields | `csrf_token` |
| `[debug-code]` | Debug patterns in JS | `console.log` |
| `[sensitive-comment]` | Sensitive HTML comments | `<!-- TODO: fix auth -->` |
| `[api-key]` | Detected API keys/secrets | `sk_live_****` |
| `[ajax-endpoint]` | AJAX/XHR endpoints | `/api/data` |
| `[waf-detected]` | WAF/CDN detection | `Cloudflare` |
| `[backup-probe]` | Backup file paths | `/config.php.bak` |
| `[source-map]` | JS source maps | `app.js.map` |
| `[service-worker]` | Service workers | `/sw.js` |
| `[subdomain]` | Discovered subdomains | `api.example.com` |
| `[aws-s3]` | AWS S3 buckets | `bucket.s3.amazonaws.com` |
| `[external]` | URLs from external sources | Wayback/CommonCrawl |

---

## 📝 Examples

### Bug Bounty Reconnaissance

```bash
# Full recon on a target with all features
./ultrafinder -u https://target.com \
  -d 3 \
  -t 20 \
  --stealth \
  --deep \
  --all-sources \
  --subs \
  -o target_recon.txt
```

### API Endpoint Discovery

```bash
# Focus on finding API endpoints
./ultrafinder -u https://api.target.com \
  --deep \
  -v \
  -o api_endpoints.txt
```

### Stealthy Scan with Proxy

```bash
# Route through Burp Suite with stealth mode
./ultrafinder -u https://target.com \
  --stealth \
  -p http://127.0.0.1:8080 \
  -o scan.txt
```

---

## 🏗️ Project Structure

```
UltraFinder/
├── main.go              # CLI entry point (Cobra)
├── go.mod               # Go module file
├── README.md            # Documentation
└── core/
    ├── crawler.go       # Main Colly-based web crawler
    ├── params.go        # Sensitive parameter detection
    ├── sources.go       # External sources (Wayback, CommonCrawl, OTX)
    ├── linkfinder.go    # JavaScript endpoint extraction
    ├── sensitive.go     # Sensitive path/header detection
    ├── deepanalysis.go  # API key, WAF, backup detection
    ├── stealth.go       # Anti-bot evasion features
    ├── output.go        # Colored output handling
    └── utils.go         # Utility functions
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 💖 Sponsor

If you find UltraFinder useful, please consider supporting the development!

<p align="center">
  <a href="https://www.paypal.com/ncp/payment/KRJ9SS2HJM57J">
    <img src="https://img.shields.io/badge/Sponsor-PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Sponsor via PayPal">
  </a>
</p>

<p align="center">
  <a href="https://www.paypal.com/ncp/payment/KRJ9SS2HJM57J">
    <strong>☕ Buy me a coffee via PayPal</strong>
  </a>
</p>

Your support helps maintain and improve this tool!

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper permission before scanning any target. The author is not responsible for any misuse or damage caused by this tool.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**veex0x01**

---

<p align="center">
  <strong>⭐ Star this repo if you find it useful! ⭐</strong>
</p>
