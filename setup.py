from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="desicon-seal",
    version="1.0.5",
    author="Desicon",
    author_email="support+seal@desicon.ai",
    description="Zero-latency App-Layer WAF, Automated SRE Logging, and AI Rescue Engine.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Desicon-AI/grumpy-python",
    options={"build": {"build_base": "build-seal"}},
    packages=find_packages(include=["seal", "seal.*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    install_requires=[
        "requests>=2.25.1",
    ],
)
