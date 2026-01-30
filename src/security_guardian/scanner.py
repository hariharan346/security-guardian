import re
import math
import os
import subprocess
from typing import List, Set
from .models import ScanResult, Severity, ScanSummary
from .policy import PolicyEngine

class SecretScanner:
    # Industry-standard safe extensions for source code scanning
    SAFE_EXTENSIONS = {
        # Code
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".c", ".cpp", ".cs", ".swift", ".rs", ".kt", ".scala", ".pl", ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1",
        # Config & Data
        ".json", ".yaml", ".yml", ".toml", ".ini", ".xml", ".properties", ".conf", ".config", ".env", ".tf", ".hcl",
        # Web
        ".html", ".htm", ".css", ".scss", ".less", ".vue", ".svelte",
        # Docs (Often contain secrets in examples)
        ".md", ".rst", ".txt"
    }

    def __init__(self, policy: PolicyEngine, exclude_patterns: List[str] = None, scan_all_files: bool = False):
        self.policy = policy
        self.exclude_patterns = exclude_patterns or []
        self.scan_all_files = scan_all_files
        
        # Default excludes to prevent scanning binary/system directories
        default_excludes = [
            ".git", ".svn", ".hg", "__pycache__", 
            ".venv", "venv", "env", "node_modules",
            "dist", "build", "*.egg-info", "target", "bin", "obj"
        ]
        for exc in default_excludes:
            if exc not in self.exclude_patterns:
                self.exclude_patterns.append(exc)
        
        self.results: List[ScanResult] = []

    def _is_excluded(self, path: str) -> bool:
        path = os.path.normpath(path)
        for pattern in self.exclude_patterns:
            # Simple substring match can be risky, but sufficient for now.
            pattern = os.path.normpath(pattern)
            if pattern in path:
                return True
        return False

    def _run_git_cmd(self, args: List[str], cwd: str) -> List[str]:
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=cwd,
                capture_output=True,
                text=True,
                check=True
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

    def get_git_tracked_files(self, root_path: str) -> List[str]:
        return self._run_git_cmd(["ls-files"], cwd=root_path)

    def get_git_staged_files(self, root_path: str) -> List[str]:
        return self._run_git_cmd(["diff", "--name-only", "--cached"], cwd=root_path)
    
    def get_git_untracked_files(self, root_path: str) -> List[str]:
         return self._run_git_cmd(["ls-files", "--others", "--exclude-standard"], cwd=root_path)

    def scan_path(self, path: str, mode: str = "default"):
        """
        Scans a path based on the selected mode.
        modes: 'default', 'staged', 'all', 'untracked'
        """
        path = os.path.abspath(path)
        
        if os.path.isfile(path):
            self._scan_file(path)
            return

        files_to_scan: Set[str] = set()
        
        # Detect if this is a git repo
        is_git_repo = os.path.exists(os.path.join(path, ".git")) or self._run_git_cmd(["rev-parse", "--is-inside-work-tree"], cwd=path)

        if not is_git_repo and mode in ["default", "staged"]:
            # Fallback to walking directory if not a git repo but asked for default scan
            # But technically 'staged' makes no sense without git.
            # We'll treat 'default' as 'walk safe files' if no git.
            print(f"[INFO] Not a git repository. Falling back to disk enumeration.")
            self._walk_and_scan(path)
            return

        if mode == "staged":
            # Scan only staged files
            relative_paths = self.get_git_staged_files(path)
            files_to_scan.update([os.path.join(path, p) for p in relative_paths])
            
        elif mode == "default":
            # Scan tracked files only
            relative_paths = self.get_git_tracked_files(path)
            files_to_scan.update([os.path.join(path, p) for p in relative_paths])
            
        elif mode == "untracked":
             # Tracked + Untracked
            tracked = self.get_git_tracked_files(path)
            untracked = self.get_git_untracked_files(path)
            files_to_scan.update([os.path.join(path, p) for p in tracked + untracked])
            
        elif mode == "all-files":
             # Scan everything explicitly
             self._walk_and_scan(path)
             return

        # Process the collected list
        for full_path in files_to_scan:
            if not os.path.exists(full_path):
                continue
            if self._is_excluded(full_path):
                continue
            self._scan_file(full_path)

    def _walk_and_scan(self, path: str):
        for root, dirs, files in os.walk(path):
            # Exclude directories
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
            
            for name in files:
                full_path = os.path.join(root, name)
                if not self._is_excluded(full_path):
                    self._scan_file(full_path)

    def _is_binary(self, filepath: str) -> bool:
        """Checks if a file is binary by looking for null bytes in the first 1KB."""
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
                if b'\0' in chunk:
                    return True
        except Exception:
            return True
        return False

    def _scan_file(self, filepath: str):
        # 0. Check Extension (unless --all-files is ON)
        # In strict Git modes, we STILL filter by extension unless user forces all-files.
        if not self.scan_all_files:
            _, ext = os.path.splitext(filepath)
            if ext.lower() not in self.SAFE_EXTENSIONS:
                return

        # 1. Skip if binary
        if self._is_binary(filepath):
            return

        try:
            # 2. Open as text with error handling
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for i, line in enumerate(lines, 1):
                    self._scan_line(filepath, i, line)
        except Exception:
            pass

    def _scan_line(self, filepath: str, line_num: int, line: str):
        found_match = False
        
        # 1. Regex Scan
        for pattern in self.policy.patterns:
            compiled_regex = pattern.get("compiled")
            if not compiled_regex:
                continue

            try:
                if compiled_regex.search(line):
                    found_match = True
                    
                    # Determine Severity (Context Aware)
                    severity = pattern["severity"]
                    detected_name = pattern["name"]
                    
                    if severity == Severity.MEDIUM:
                        for kw in self.policy.context_keywords:
                            if kw.lower() in line.lower():
                                severity = Severity.HIGH
                                detected_name += f" (Context: {kw})"
                                break
                                
                    self.results.append(ScanResult(
                        file_path=filepath,
                        line_number=line_num,
                        secret_type=detected_name,
                        severity=severity,
                        content_snippet=line.strip()
                    ))
            except Exception:
                continue

        # 2. Entropy Scan (If no regex match)
        if not found_match:
            self._scan_entropy(filepath, line_num, line)

    def _scan_entropy(self, filepath: str, line_num: int, line: str):
         # Extract potential secret strings (assignments)
         strings = re.findall(r"['\"]([A-Za-z0-9/+]{16,})['\"]", line)
         for s in strings:
             entropy = self._calculate_entropy(s)
             if entropy > 4.5: # Threshold
                 self.results.append(ScanResult(
                    file_path=filepath,
                    line_number=line_num,
                    secret_type=f"High Entropy String ({entropy:.2f})",
                    severity=Severity.MEDIUM,
                    content_snippet=line.strip()
                ))

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return - sum([p * math.log(p) / math.log(2.0) for p in prob])
