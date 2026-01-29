from setuptools import setup, find_packages

setup(
    name="security_guardian",
    version="1.2.0",
    description="Enterprise Secret Leakage Prevention Tool",
    author="DevSecOps Platform Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        # No external dependencies for core scanner to ensure portability
    ],
    entry_points={
        "console_scripts": [
            "security-guardian=security_guardian.cli:main",
        ],
    },
    python_requires=">=3.9",
)
