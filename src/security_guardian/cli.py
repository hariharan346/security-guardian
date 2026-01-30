import argparse
import sys
import json
import os
from .policy import PolicyEngine
from .scanner import SecretScanner
from .validator import SecretValidator
from .models import Severity
from .hygiene import check_hygiene

import stat

def install_hook():
    """
    Installs the git pre-commit hook.
    """
    git_dir = ".git"
    if not os.path.exists(git_dir):
        print("[ERROR] .git directory not found. Are you in a Git repository?")
        sys.exit(1)
        
    hook_path = os.path.join(git_dir, "hooks", "pre-commit")
    
    # Check if hook already exists
    if os.path.exists(hook_path):
        print(f"[INFO] Overwriting existing pre-commit hook at {hook_path}")
        
    # Updated hook content to use --staged
    hook_content = """#!/bin/sh
echo "Running Security Guardian..."
# Scan current directory in staged mode
security-guardian scan . --staged
if [ $? -ne 0 ]; then
    echo "❌ Security Check Failed. Commit Blocked."
    exit 1
fi
echo "✅ Security Check Passed."
exit 0
"""
    
    try:
        with open(hook_path, "w", encoding='utf-8') as f:
            f.write(hook_content)
        
        # Make executable (chmod +x)
        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC)
        
        print("[SUCCESS] Pre-commit hook installed successfully.")
        print(f"   Location: {hook_path}")
        print("   Behavior: Runs 'security-guardian scan . --staged' before every commit.")
        
    except Exception as e:
        print(f"[ERROR] Error installing hook: {e}")
        sys.exit(1)

def run_scan(args):
    should_block = False
    
    # Phase 0: Hygiene Checks
    hygiene_block, hygiene_messages = check_hygiene()
    if hygiene_messages:
        print("\n[HYGIENE CHECK]")
        for msg in hygiene_messages:
            print(msg)
        print("-" * 40)
        
    if hygiene_block:
        should_block = True

    # Phase 1: Determine Mode
    # Priority: Staged > All-Files > Include-Untracked > Default
    scan_mode = "default"
    if args.staged:
        scan_mode = "staged"
    elif args.all_files:
        scan_mode = "all-files"
    elif args.include_untracked:
        scan_mode = "untracked"

    # Phase 2: Load Ignore File
    ignore_file_path = ".security-guardian-ignore"
    if os.path.exists(ignore_file_path):
        with open(ignore_file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    args.exclude.append(line)
    
    # Initialize Components
    policy = PolicyEngine()
    # Note: scan_all_files arg in init is for extension filtering override
    # If mode is all-files, we want to disable extension filtering in scanner too
    disable_ext_filter = (scan_mode == "all-files")
    
    scanner = SecretScanner(policy, exclude_patterns=args.exclude, scan_all_files=disable_ext_filter)
    
    # Run Scan
    for path in args.paths:
        if args.verbose:
            print(f"[INFO] Scanning {path} (Mode: {scan_mode})")
        scanner.scan_path(path, mode=scan_mode)
    
    # Determine Block/Warn (from Scan)
    # should_block is already potentially True from hygiene
    results_out = []
    
    for issue in scanner.results:
        action = policy.get_action(issue.severity)
        if action == "BLOCK":
            should_block = True
            
        # Optional Verification
        val_status = "N/A"
        if args.validate:
            val_status = SecretValidator.validate(issue.secret_type, issue.content_snippet)
            
        results_out.append({
            "file": issue.file_path,
            "line": issue.line_number,
            "type": issue.secret_type,
            "severity": issue.severity.value,
            "action": action,
            "content": issue.content_snippet,
            "validation": val_status
        })

    # Output
    if args.format == "json":
        print(json.dumps({"blocking": should_block, "issues": results_out}, indent=2))
    else:
        # Text Output
        if not results_out:
            print(f"[OK] No secrets found ({scan_mode} mode).")
        else:
            print(f"\n[ALERT] SCAN COMPLETE: Issues Found")
            for res in results_out:
                icon = "[X]" if res['action'] == "BLOCK" else "[!]"
                print(f"{icon} [{res['severity']}] {res['type']} -> {res['action']}")
                print(f"   File: {res['file']}:{res['line']}")
                print(f"   Snippet: {res['content']}")
                if args.validate:
                    print(f"   Cloud Check: {res['validation']}")
                print("-" * 40)
    
    # Exit Code
    if should_block:
        sys.exit(1)
    else:
        sys.exit(0)

def main():
    # Ensure generated output handles emojis correctly on all platforms
    if sys.stdout.encoding != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except AttributeError:
            # Python < 3.7 or weird environment
            pass

    parser = argparse.ArgumentParser(description="Security Guardian - Enterprise Secret Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Command to execute")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan files or directories for secrets")
    scan_parser.add_argument("paths", nargs="+", help="Paths to file or directory to scan")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    scan_parser.add_argument("--validate", action="store_true", help="Attempt to validate found secrets")
    scan_parser.add_argument("--exclude", nargs="+", default=[], help="Patterns to exclude from scan")
    scan_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # Mode Flags
    scan_parser.add_argument("--all-files", action="store_true", help="Scan ALL files (slower, but covers everything). Default: Safe Extensions + Tracked Files only.")
    scan_parser.add_argument("--staged", action="store_true", help="Scan ONLY staged files (Git Pre-commit mode).")
    scan_parser.add_argument("--include-untracked", action="store_true", help="Include untracked files (Git default ignores honored).")

    scan_parser.set_defaults(func=run_scan)

    # Command: install-hook
    hook_parser = subparsers.add_parser("install-hook", help="Install Git pre-commit hook")
    hook_parser.set_defaults(func=lambda args: install_hook())
    
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
