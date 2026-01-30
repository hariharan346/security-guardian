import os
import shutil
import tempfile
import subprocess
import sys

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'src'))
sys.path.insert(0, SRC_DIR)

def run():
    test_dir = tempfile.mkdtemp()
    print(f"Test Dir: {test_dir}")
    old_cwd = os.getcwd()
    os.chdir(test_dir)
    
    try:
        subprocess.check_call(["git", "init"], stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "config", "user.email", "you@example.com"], stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "config", "user.name", "Your Name"], stdout=subprocess.DEVNULL)

        with open(".env", "w") as f:
            f.write("DB_PASS=1234")
        
        subprocess.check_call(["git", "add", ".env"], stdout=subprocess.DEVNULL)
        
        # Run CLI
        env = os.environ.copy()
        env["PYTHONPATH"] = SRC_DIR
        
        cmd = [sys.executable, "-m", "security_guardian.cli", "scan", "."]
        print(f"Running: {cmd}")
        
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True
        )
        
        print("--- STDOUT ---")
        print(result.stdout)
        print("--- STDERR ---")
        print(result.stderr)
        print(f"Return Code: {result.returncode}")
        
    finally:
        os.chdir(old_cwd)
        try:
            shutil.rmtree(test_dir)
        except:
            pass

if __name__ == "__main__":
    run()
