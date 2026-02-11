from setuptools import setup, find_packages


setup(
    name="sentinel-guard",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests==2.32.3",
        "PyYAML==6.0.2",
    ],
    author="Sentinel Team",
    description="Security middleware for AI Agents",
)
