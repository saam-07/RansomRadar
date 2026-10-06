from setuptools import setup, find_packages

setup(
    name="adaptshield",
    version="0.1.0",
    packages=find_packages(include=["adaptshield", "adaptshield.*"]),
    python_requires=">=3.10",
)
