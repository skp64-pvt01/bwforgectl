from setuptools import find_packages, setup

setup(
    name="bwforgectl",
    version="1.0.0",
    description="Manage SSH keys and Git credentials via Bitwarden vault",
    author="pilakkat1964",
    author_email="pilakkat1964@gmail.com",
    license="MIT",
    packages=find_packages(include=["bw_forge_ctl", "bw_forge_ctl.*"]),
    python_requires=">=3.10",
    install_requires=["cryptography>=41"],
    entry_points={
        "console_scripts": [
            "bwforgectl=bw_forge_ctl.cli:main",
            "ssh-bw=bw_forge_ctl.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
    ],
)
