from setuptools import setup, find_packages


setup(
    name="sentinel-guard",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "pyyaml",
    ],
    author="Sentinel Team",
    description="Security middleware for AI Agents",
)
