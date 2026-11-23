# Password Strength & Policy Analyzer (`pwcheck`)

An interactive, editorial-grade security analysis suite and web interface based on the `pwcheck` password policy and entropy engine. It audits candidate secrets, assesses entropy against real-world attack models, identifies vulnerabilities, and demonstrates cryptographic hashing primitives (SHA-256, salting, HMAC, and avalanche effect).

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?logo=typescript)
![React](https://img.shields.io/badge/React-19-61dafb?logo=react)
![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-v4-38bdf8?logo=tailwindcss)
![Vite](https://img.shields.io/badge/Vite-7-646cff?logo=vite)

---

## 📌 Project Overview

This project provides a comprehensive real-time password strength inspector, vulnerability auditor, and cryptographic learning playground.

### Key Capabilities
- **Policy Compliance Auditing**: Evaluates candidate passwords against 8 core security controls across **Baseline** (NIST SP 800-63B aligned) and **Strict** corporate security profiles.
- **Adjusted Entropy Estimation**: Calculates theoretical raw entropy ($L \times \log_2(\text{Pool})$) and applies realistic penalties for repeated tokens, dictionary words, keyboard walks, leetspeak substitutions, and dates.
- **Crack Time Modeling**: Estimates brute-force and dictionary search times across multiple adversary tiers:
  - Online throttled service (10 attempts/sec)
  - Online unthrottled service (1,000 attempts/sec)
  - Fast offline CPU attack (100,000,000 attempts/sec)
  - Multi-GPU cluster attack ($10^{11}$ attempts/sec)
- **Zero-Dependency Cryptographic Demonstrations**:
  - Pure TypeScript/JS implementation of **FIPS 180-4 SHA-256** without external crypto libraries.
  - Salted hash demonstration with live randomized 16-byte hex salts.
  - **Bit Avalanche Effect Visualizer**: Illustrates cryptographic diffusion by showing the percentage and bit positions flipped in the digest when a single input bit changes.
- **Passphrase & Generator Support**: Generates secure random multi-word passphrases or high-entropy alphanumeric passwords.

---

## 🛠️ Security Controls Evaluated

| Control ID | Rule Name | Description | Severity |
| :--- | :--- | :--- | :--- |
| `SEC-01` | **Minimum Length** | Requires 8+ characters (Baseline) or 12+ characters (Strict). | Critical |
| `SEC-02` | **Character Diversity** | Requires uppercase, lowercase, numbers, and symbols. | High |
| `SEC-03` | **Denylist / Common Passwords** | Checks against Top 10,000 common passwords. | Critical |
| `SEC-04` | **Dictionary Words** | Identifies embedded dictionary words and English tokens. | High |
| `SEC-05` | **Repetitive & Sequential Patterns** | Flags character repeats (`aaa`) and sequences (`12345`, `abcdef`). | High |
| `SEC-06` | **Keyboard Spatial Walks** | Detects qwerty rows and keyboard walk patterns (`qwerty`, `asdf`). | High |
| `SEC-07` | **Leetspeak Substitutions** | Unmasks common obfuscation techniques (e.g., `@` for `a`, `0` for `o`). | Medium |
| `SEC-08` | **Date & Year Signatures** | Flags embedded years (1900–2099) and common date formats. | Medium |

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v18.0.0 or higher recommended)
- `npm`, `pnpm`, or `yarn`

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Viggi-dotcom/pwcheck.git
   cd python-password-strength-analyzer
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the local development server:**
   ```bash
   npm run dev
   ```

4. **Open in browser:**
   Navigate to [http://localhost:5173](http://localhost:5173).

---

## 📦 Building for Production

To create a single-file portable production build:

```bash
npm run build
```

The compiled bundle will be output to the `dist/` directory (configured via `vite-plugin-singlefile` to produce a self-contained, portable `dist/index.html`).

To preview the production build locally:
```bash
npm run preview
```

---

## 📁 Project Architecture

```
python-password-strength-analyzer/
├── index.html                  # HTML entry point with web fonts & metadata
├── package.json                # Project dependencies and npm scripts
├── tsconfig.json               # TypeScript configuration
├── vite.config.ts              # Vite & single-file bundle configuration
└── src/
    ├── main.tsx                # React application bootstrap
    ├── App.tsx                 # Root layout and theme wrapper
    ├── index.css               # Tailwind CSS v4 styling & typography
    ├── assets/                 # Background textures and visual plates
    ├── components/
    │   ├── Analyzer.tsx        # Interactive password analyzer & live inspector
    │   ├── Sections.tsx        # Hero, CLI transcript, policy matrix & source viewer
    │   └── ui.tsx              # Reusable UI controls and typographic elements
    ├── lib/
    │   └── analyzer.ts         # Pure cryptographic, entropy, and policy engine
    └── utils/
        └── cn.ts               # Classname merge utility
```

---

## 🔒 Security & Privacy Notice

All analyses, entropy calculations, and SHA-256 hash operations execute **100% client-side in your browser memory**. No credentials, partial strings, or tokens are ever logged, cached to disk, or sent across any network.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
