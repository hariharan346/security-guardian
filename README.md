# Security Guardian 🛡️

> **The Enterprise-Grade, Cloud-Native Secret Prevention Platform.**

**Security Guardian** is a robust DevSecOps tool designed to preventing credential leakage in large-scale applications. It combines regex-based detection, entropy analysis, and context-aware intelligence to block real threats while minimizing false positives.

Unlike simple scripts, this is a **versioned, distributable platform tool** that enforces "Zero Leakage" policies throughout your CI/CD pipeline.

---

## 🚀 Key Features

*   **� Intelligent Scanning**: Detects API keys, private keys, passwords, and cloud credentials (AWS, GitHub, etc.).
*   **🧠 Context-Aware Engine**: Distinguishes between critical leaks (e.g., `prod_db_password`) and test configurations.
*   **🔢 Entropy Analysis**: Identifies high-randomness strings that standard regex might miss.
*   **⚓ Git Pre-commit Hook**: Opt-in hook to automatically scan changed files before every commit.
*   **📐 Strict Hygiene Rules**: Enforces `.env` file best practices to prevent accidental check-ins.
*   **📦 Python Package**: Easily distributable via `pip` for use in any environment (Windows, Linux, macOS).

---

## � Installation

Install the package via pip:

```bash
pip install security-guardian
```

---

## 🛠️ Usage

### 1. Manual Scan
Run a scan on your source code or any directory:

```bash
# Scan current directory
security-guardian scan .

# Scan specific folder
security-guardian scan src/

# JSON Output (Great for Dashboards)
security-guardian scan src/ --format json
```

### 2. Scanning Strategy 🆕

**Default Mode (Tracked Only):**
By default, `security-guardian` scans **only Git-tracked files**. This mirrors how CI/CD pipelines work and ensures we don't scan local junk files.
- ✅ Scans: `git ls-files`
- ✅ Filters: Only supports safe source extensions (`.py`, `.js`, `.json`, etc.)
- 🚫 Ignores: Untracked files, binaries, `.git/`, vendor folders.

**Include Untracked (`--include-untracked`):**
If you want to scan local files that haven't been committed yet (but are not ignored), use this flag.
- ✅ Scans: Tracked files + Untracked files (respects `.gitignore`)
- ⚠️ Useful for: Checking a new script before `git add`.

**All-Files Mode (`--all-files`):**
For deep audits, scan **everything** on disk recursively.
- ✅ Scans: All files in directory.
- ✅ Filters: Ignores `.git/` and standard vendor paths.
- ⚠️ Warning: Slower. Use for deep security audits.

```bash
# Standard Scan (Recommended)
security-guardian scan .

# Check new uncommitted work
security-guardian scan . --include-untracked

# Audit everything
security-guardian scan . --all-files
```

> **Note:** Binary files are always safely skipped in all modes to prevent crashes.

### 3. Install Pre-commit Hook (Recommended)
You can opt-in to install a local git hook that prevents you from committing secrets. This hook runs ONLY when you verify it's safe.

```bash
security-guardian install-hook
```

**How it works:**
1.  Verifies you are in a valid Git repository.
2.  Installs a script in `.git/hooks/pre-commit`.
3.  **Blocks** any commit containing HIGH severity secrets.
4.  **Allows** everything else (including Warnings).

---

## 📐 Git Hygiene Policy

We enforce strict rules regarding `.env` files to prevent the most common source of leaks. These rules are applied **before** the secret scan.

| Condition | Action | Reason |
| :--- | :--- | :--- |
| **`.env` not present** | ✅ **PASS** | Clean state. Safe. |
| **`.env` in `.gitignore`** | ✅ **PASS** | Properly ignored. Safe. |
| **`.env` NOT in `.gitignore`** | ⚠️ **WARN** | **Risk:** High chance of future accidental commit. |
| **`.gitignore` missing** | ⚠️ **WARN** | **Risk:** Repository is not configured correctly. |
| **`.env` TRACKED by git** | ❌ **BLOCK** | **REAL LEAK DETECTED.** Immediate action required. |

> **Note:** We do **NOT** scan the contents of `.env` files by default. We assume any tracked `.env` is a security violation regardless of content.

---

## 🛡️ Security Philosophy

We follow a **"Noise-Free"** philosophy suitable for high-velocity engineering teams:

1.  **Block on Real Risk**: Only HIGH severity issues (e.g., AWS Secret Keys, Production Passwords) break the build or block commits.
2.  **Warn on Hygiene**: Issues like unignored `.env` files generate warnings but do not stop development flow unless they become actual leaks.
3.  **Local First**: Security starts on the developer's machine via hooks, not just in the CI/CD pipeline.

---

## 🔄 Updates

To update to the latest version:

```bash
pip install --upgrade security-guardian
```

*Note: You do not need to reinstall the hook after updating the package.*