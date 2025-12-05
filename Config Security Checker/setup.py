from setuptools import setup, find_packages

setup(
    name="config_security_checker",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "rich",
        "cryptography"
    ],
    entry_points={
        "console_scripts": [
            "config-checker=config_security_checker.cli:main",
        ]
    }
)
