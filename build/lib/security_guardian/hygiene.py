import os
import subprocess
from typing import Tuple, List

def check_hygiene() -> Tuple[bool, List[str]]:
    """
    Checks for git hygiene violations mainly focusing on .env files.
    Returns:
        tuple: (should_block: bool, messages: List[str])
    """
    messages = []
    should_block = False
    
    env_path = ".env"
    gitignore_path = ".gitignore"
    
    # RULE 1: .env NOT present -> Pass
    if not os.path.exists(env_path):
        return False, []

    # Check if .env is tracked by git (RULE 5)
    # git ls-files .env --error-unmatch
    try:
        # Use subprocess to check git tracking
        # We redirect stderr to devnull to avoid noise if not tracked
        subprocess.check_call(
            ["git", "ls-files", "--error-unmatch", env_path], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        # If call succeeds, file IS tracked
        messages.append("❌ [BLOCK] .env file is TRACKED by git! (Real Leak Risk)")
        should_block = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        # File is NOT tracked (or git not present/error), continue to other checks
        pass

    if should_block:
        return True, messages

    # RULE 3: .env present BUT .gitignore missing -> WARN
    if not os.path.exists(gitignore_path):
        messages.append("⚠️ [WARN] .env exists but .gitignore is MISSING.")
        return False, messages

    # RULE 2 & 4: Check if .env is ignored
    # git check-ignore -q .env
    try:
        subprocess.check_call(
            ["git", "check-ignore", "-q", env_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # If succeeds, .env is ignored -> RULE 2 (Pass)
        return False, []
    except (subprocess.CalledProcessError, FileNotFoundError):
        # If failed, .env is NOT ignored -> RULE 4 (Warn)
        messages.append("⚠️ [WARN] .env exists but is NOT listed in .gitignore.")
        return False, messages
