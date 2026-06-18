from setuptools import find_packages, setup

setup(
    name="ssh-bw",
    version="1.0.0",
    description="Sync local SSH key pairs (and PGP notes) with a Bitwarden vault",
    author="pilakkat1964",
    author_email="pilakkat1964@gmail.com",
    license="MIT",
    packages=find_packages(include=["ssh_bw", "ssh_bw.*"]),
    python_requires=">=3.10",
    install_requires=["cryptography>=41"],
    entry_points={
        "console_scripts": [
            "ssh-bw=ssh_bw.cli:main",
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
