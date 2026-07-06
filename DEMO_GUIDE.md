Scenario 1: Accidental Secret Commit

What I will say:

“I’ll first show how the tool prevents a developer from accidentally committing an AWS access key.”

Open the terminal.
Create a file called leaked_config.py.
# Temporary configuration
aws_key = "AKIAIOSFODNN7EXAMPLE"
Try to commit the file.
git add leaked_config.py
git commit -m "Quick fix for production"
The pre-commit hook detects the AWS key and blocks the commit.

Expected output:

BLOCKING: High severity secrets detected.

What I will explain:

“The important point here is that the secret is stopped before it reaches GitHub or the central repository. The developer gets immediate feedback on their local machine, so the issue can be fixed before it becomes a security incident.”

Scenario 2: Test Credential vs Production Credential

What I will say:

“Many secret scanning tools generate too many alerts. This project uses context to decide whether something should be a warning or a block.”

Update the file with a test password.
# Test database password
test_db_pass = "password123"
Run the scanner.
python src/scan.py leaked_config.py

Expected output:

[MEDIUM] -> Action: WARN

What I will explain:

“This is marked as a warning because it is clearly a test credential. The developer is informed, but their work is not blocked unnecessarily.”

Now change it to a production password.
# Production database password
prod_db_pass = "password123"
Run the scanner again.
python src/scan.py leaked_config.py

Expected output:

[HIGH] -> Action: BLOCK

What I will explain:

“Once the tool sees production-related context, it treats the same password differently. It increases the severity and blocks the action because production credentials can expose real systems and customer data.”

Scenario 3: Cloud Validation

What I will say:

“Finding a key is useful, but security teams also need to know whether that key is active and dangerous.”

Run the validation command.
python src/scan.py --validate tests/test_secrets.txt

Expected output:

Cloud Check: Valid Test Key

What I will explain:

“This feature can be connected to cloud-provider or platform APIs such as AWS and GitHub. Once a key is detected, the system can check whether it is active. If the key is active, the next step would be to alert the security team and rotate or revoke the credential immediately.”

Scenario 4: Detecting Unknown Secrets with Entropy

What I will say:

“Not every secret follows a known pattern like an AWS key. Some secrets are random strings, so regex detection alone is not enough.”

Open tests/test_entropy.txt.
high_entropy = "7Fz/3x9@1qP#m$Lk"
Run the scanner.
python src/scan.py tests/test_entropy.txt

Expected output:

High Entropy String (Score: 4.xx)

What I will explain:

“This string does not match a known AWS, GitHub, or database password pattern. However, the entropy calculation identifies that it is unusually random. Random-looking strings are often tokens, API keys, or generated credentials. This helps identify secrets that traditional pattern matching may miss.”
