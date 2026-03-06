# BlackMarker — Burp Suite Sensitive Data Masking Extension

**Visual masking of sensitive data in Burp Suite for safe screen sharing and screenshots.**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![API](https://img.shields.io/badge/Burp_API-Montoya-green)
![Java](https://img.shields.io/badge/Java-17%2B-orange)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

---

## Overview

BlackMarker adds a **"BlackMarker"** tab to every HTTP message editor in Burp Suite (Proxy, Repeater, Intruder, Scanner, etc.). It visually masks sensitive data — **without modifying the actual HTTP traffic** — so you can safely share your screen, record demos, or take screenshots.

## Features

### Detection Engine
- **60+ built-in regex rules** covering PII, auth tokens, passwords, infrastructure, crypto keys
- **Entropy-based detection** — catches random-looking secrets via Shannon entropy analysis
- **Auto-learn** — automatically tracks session cookies, CSRF tokens, and auth tokens from live traffic
- **Capture group masking** — rules can target specific parts of a match (e.g. only the value in `"ssn": "123-45-6789"`)
- **Edge preservation** — long values show first/last characters for context (e.g. `eyJ████████████g`)

### Visual Display
- **Color-coded categories** — PII (blue), Auth (red), Infrastructure (orange), Crypto (purple), Session (green)
- **Click-to-reveal** — click any masked region to toggle the original value
- **Right-click manual masking** — select text → right-click → "Mask selection"
- **HTTP syntax coloring** — header names in dark blue, request line in dark red
- **Hide uninteresting headers** — toggle to collapse standard headers (Accept, User-Agent, Cache-Control, etc.)
- **Line wrapping** — long masked runs wrap correctly at any character
- **Truncation** — optionally shorten long masked strings (e.g. JWTs) with ellipsis: `████…████`
- **Monochrome mode** — single color for all categories

### Customization
- **Global mask character** — change `█` to any character (`*`, `X`, `#`, etc.)
- **Per-category color overrides** — full control over foreground and background colors
- **Custom categories** — define your own with name and colors
- **Rule editor** — add/edit/remove rules with live regex validation and test field
- **Import/export rules** — JSON format for sharing between teams

### Integration
- **"BlackMarker" tab** in every HTTP message editor
- **Context menu** — right-click → "Copy Masked Request/Response" to clipboard
- **Main BlackMarker tab** — rules management, settings, live test, auto-learn dashboard
- **Persistence** — all rules and settings survive Burp restarts via Persistence API

## Rule Categories

| Category | Color | Examples |
|----------|-------|----------|
| **PII** | 🔵 Blue | Email, phone, SSN, credit card, IP, MAC, date of birth |
| **Auth** | 🔴 Red | JWT, Bearer, API keys (AWS, GCP, GitHub, Slack, Stripe, Telegram) |
| **Infrastructure** | 🟠 Orange | Internal IPs, S3 buckets, database URLs, Docker registry, ARN |
| **Crypto** | 🟣 Purple | PEM keys, Bitcoin/Ethereum addresses, hashes |
| **Session** | 🟢 Green | Cookies, CSRF tokens, Session IDs, OAuth state/nonce |
| **Custom** | ⚪ Gray | User-defined rules |

## Installation

### Build from Source

**Option A — Gradle (requires Java 17+ and Gradle 7+):**
```bash
./gradlew jar
# Output: build/libs/BlackMarker-1.0.0.jar
```

**Option B — Docker (no local Java required):**
```bash
docker build --target artifact --output build/ .
# Output: build/BlackMarker-1.0.0.jar
```

### Load into Burp Suite

1. Open Burp Suite (Professional or Community)
2. Go to **Extensions → Installed → Add**
3. Set **Extension type: Java**
4. Select `BlackMarker-1.0.0.jar`
5. Click **Next** — you should see "BlackMarker loaded" in the output

## Usage

### Viewing Masked Traffic
1. Open any HTTP request/response in Proxy, Repeater, or other tools
2. Switch to the **"BlackMarker"** tab (next to Raw / Headers / Hex)
3. Sensitive data is masked with colored highlights by category

### Click-to-Reveal
- Click any masked region to reveal the original value
- Click again to re-mask it

### Manual Masking
- Select any text in the BlackMarker view
- Right-click → **"█ Mask selection"**
- Right-click → **"✖ Clear manual masks"** to undo

### Toolbar Controls
| Button | Action |
|--------|--------|
| **Masking On/Off** | Toggle masking |
| **Copy Masked** | Copy masked text to clipboard |
| **Wrap** | Toggle line wrapping |
| **Hide Headers** | Toggle uninteresting headers |

### Managing Rules
1. Go to the main **BlackMarker** tab in Burp
2. **Rules** sub-tab — view, add, edit, delete rules
3. Filter by category, toggle groups with Enable/Disable All
4. Use **Import/Export** buttons for JSON backup

### Live Testing
1. Main **BlackMarker** tab → **Live Test**
2. Paste HTTP traffic in the input field
3. Click **"Run Masking Test"** — see masked output with colored highlights

### Settings
- **Appearance** — monochrome mode, global mask character, truncation settings
- **Category Colors** — click table cells to change colors per category
- **Custom Categories** — add your own categories with custom colors
- **Entropy Detection** — configure threshold, min/max string length

## Architecture

```
blackmarker/
├── BlackMarkerExtension.java          # Entry point, Burp registration
├── engine/
│   └── MaskingEngine.java             # Core masking (regex + entropy + session)
├── model/
│   ├── RuleCategory.java              # Category enum
│   ├── MaskingRule.java               # Rule model
│   ├── MaskMatch.java                 # Match result
│   ├── MaskingResult.java             # Full masking result
│   ├── PluginSettings.java            # Settings singleton
│   └── CustomCategory.java            # User-defined category model
├── rules/
│   ├── DefaultRules.java              # 60+ built-in rules
│   ├── EntropyDetector.java           # Shannon entropy detection
│   └── SessionValueTracker.java       # Auto-learn session values
├── ui/
│   ├── BlackMarkerTab.java            # Main tab (rules, settings, test, auto-learn)
│   ├── RuleManagerPanel.java          # Rule management panel
│   ├── RuleTableModel.java            # JTable model for rules
│   ├── MaskedTextPane.java            # Custom JTextPane with colored masking
│   ├── MaskedRequestEditorProvider.java   # Request editor tab provider
│   ├── MaskedResponseEditorProvider.java  # Response editor tab provider
│   ├── ContextMenuProvider.java       # "Copy Masked" context menu
│   └── ColorScheme.java              # Color scheme with overrides
└── export/
    └── SessionExporter.java           # HTML/Text export
```

## Design Principles

- **Visual only** — HTTP traffic is never modified; masking is purely for display
- **Same-length replacement** — masked text has the same length as original (positions preserved for click-to-reveal)
- **Thread-safe** — ConcurrentHashMap for session tracking, CopyOnWriteArrayList for rules
- **Persistence** — rules, settings, and preferences saved via Burp Persistence API
- **Burp theme aware** — UI adapts to Burp's light/dark theme

## Adding Custom Rules

### Via UI
1. BlackMarker → Rules → **Add Rule**
2. Fill in: Name, Category, Regex, Mask char, Description
3. Use **Test Regex** to validate before saving

### Via JSON Import
```json
[
  {
    "name": "Internal Project Code",
    "regex": "PROJ-[A-Z0-9]{8,}",
    "category": "CUSTOM",
    "maskChar": "█",
    "enabled": true,
    "description": "Internal project identifiers"
  }
]
```

## Requirements

- **Burp Suite** Professional or Community (2023.1+)
- **Java 17+** (bundled with modern Burp Suite)

## License

MIT License — see [LICENSE](LICENSE) for details.
