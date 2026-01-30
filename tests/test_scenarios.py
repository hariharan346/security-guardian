import unittest
import os
import shutil
import tempfile
import subprocess
import sys

# Add src to pythonpath so we can run the module
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, SRC_DIR)

class TestSecurityGuardianScenarios(unittest.TestCase):
    def setUp(self):
        # Create a temp directory for the git repo
        self.test_dir = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        # Initialize Git Repo
        subprocess.check_call(["git", "init"], stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "config", "user.email", "you@example.com"], stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "config", "user.name", "Your Name"], stdout=subprocess.DEVNULL)

        # Paths
        self.cli_cmd = [sys.executable, "-m", "security_guardian.cli"]

    def tearDown(self):
        os.chdir(self.old_cwd)
        try:
            shutil.rmtree(self.test_dir)
        except PermissionError:
            pass # Windows file locking sometimes

    def run_cli(self, args, expect_success=True):
        """Runs the CLI and returns stdout/stderr. Asserts return code."""
        env = os.environ.copy()
        env["PYTHONPATH"] = SRC_DIR
        
        # Determine encoding to avoid crashing on Windows with emojis
        encoding = 'utf-8'
        
        result = subprocess.run(
            self.cli_cmd + args,
            env=env,
            capture_output=True,
            text=True,
            encoding=encoding,
            errors='replace' # Prevent crashing if decoding fails
        )
        
        if expect_success and result.returncode != 0:
             self.fail(f"CLI failed unexpectedly.\nStdout: {result.stdout}\nStderr: {result.stderr}")
        elif not expect_success and result.returncode == 0:
             self.fail(f"CLI succeeded unexpectedly.\nStdout: {result.stdout}")
             
        return result.stdout

    def create_file(self, filename, content):
        with open(filename, "w", encoding='utf-8') as f:
            f.write(content)

    def git_add(self, filename):
        subprocess.check_call(["git", "add", filename], stdout=subprocess.DEVNULL)

    def git_commit(self, msg):
        subprocess.check_call(["git", "commit", "-m", msg], stdout=subprocess.DEVNULL)

    def test_01_tracked_params(self):
        """Test 1: JS file with AWS key (tracked) -> MUST BLOCK"""
        print("\n[TEST] 1. Tracked AWS Key")
        self.create_file("secrets.js", 'const aws_key = "AKIAIOSFODNN7EXAMPLE";')
        self.git_add("secrets.js")
        self.git_commit("Add secret")
        
        out = self.run_cli(["scan", "."], expect_success=False)
        self.assertIn("AWS Access Key", out)
        self.assertIn("BLOCK", out)

    def test_02_weak_password(self):
        """Test 2: JS file with weak password -> MUST WARN"""
        print("\n[TEST] 2. Weak Password")
        # Avoid using 'secret' in the value as it triggers context-aware upgrade to HIGH
        self.create_file("config.js", 'const password = "weakpassword123";')
        self.git_add("config.js")
        # should pass (return 0) but show warning
        out = self.run_cli(["scan", "."]) 
        self.assertIn("Generic Password", out)
        self.assertIn("WARN", out)
        # Verify it didn't block
        self.assertNotIn("BLOCK", out)

    def test_03_untracked_default(self):
        """Test 3: Untracked file -> NOT scanned by default"""
        print("\n[TEST] 3. Untracked Default")
        # Create a secret file but don't add to git
        self.create_file("untracked_secret.py", 'aws = "AKIAIOSFODNN7EXAMPLE"')
        
        # Default scan shouldn't see it (assuming no .git fallback logic triggered incorrectly)
        out = self.run_cli(["scan", "."])
        self.assertIn("No secrets found", out)

    def test_04_include_untracked(self):
        """Test 4: Untracked file with --include-untracked -> MUST detect"""
        print("\n[TEST] 4. Include Untracked")
        self.create_file("untracked_secret.py", 'aws = "AKIAIOSFODNN7EXAMPLE"')
        
        out = self.run_cli(["scan", ".", "--include-untracked"], expect_success=False)
        self.assertIn("AWS Access Key", out)
        self.assertIn("BLOCK", out)

    def test_05_env_hygiene_tracked(self):
        """Test 5: .env tracked -> MUST BLOCK"""
        print("\n[TEST] 5. .env Tracked")
        self.create_file(".env", "DB_PASS=1234")
        self.git_add(".env")
        # Only commiting so git knows it's tracked (though add index is enough for ls-files)
        
        out = self.run_cli(["scan", "."], expect_success=False)
        self.assertIn(".env file is TRACKED", out)

    def test_06_env_hygiene_ignored(self):
        """Test 6: .env ignored -> MUST ALLOW"""
        print("\n[TEST] 6. .env Ignored")
        self.create_file(".gitignore", ".env\n")
        self.create_file(".env", "DB_PASS=1234")
        self.git_add(".gitignore")
        self.git_commit("Add ignore")
        
        out = self.run_cli(["scan", "."])
        self.assertIn("No secrets found", out)

    def test_07_staged_mode(self):
        """Test 7: Staged Mode (Pre-commit simulation)"""
        print("\n[TEST] 7. Staged Mode")
        # Create 2 files
        # 1. secrets.js (Staged) -> Should catch
        # 2. old_secret.js (Committed/Unchanged) -> Should IGNORE in staged mode?
        #    Actually pre-commit usually scans staged changes. Old files are ignored.
        
        self.create_file("old_secret.js", 'const old = "AKIAIOSFODNN7EXAMPLE";')
        self.git_add("old_secret.js")
        self.git_commit("Committed bad file")
        
        self.create_file("new_secret.js", 'const newkey = "AKIAIOSFODNN7EXAMPLE";')
        self.git_add("new_secret.js")
        
        # Run staged scan
        out = self.run_cli(["scan", ".", "--staged"], expect_success=False)
        
        # Output should mention new_secret.js
        self.assertIn("new_secret.js", out)
        # Should NOT mention old_secret.js because it wasn't staged (it was committed)
        # Wait, git diff --name-only --cached shows what is in index vs HEAD.
        # old_secret.js is in index (same as HEAD). It shows up only if modified.
        # So correct, old_secret.js should NOT be in output of staged files if unchanged.
        self.assertNotIn("old_secret.js", out)

    def test_08_binary_file(self):
         """Test 8: Binary file -> No Crash"""
         print("\n[TEST] 8. Binary File")
         # Write null bytes
         with open("data.bin", "wb") as f:
             f.write(b'\x00\x01\x02\x03')
         self.git_add("data.bin")
         
         out = self.run_cli(["scan", "."])
         self.assertIn("No secrets found", out)

if __name__ == '__main__':
    if sys.stdout.encoding != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except AttributeError:
            pass
    unittest.main()
