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
    extras_require={
        "prompt-guard": [
            "transformers>=4.44.0,<5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "sentinel-isolate=src.isolation:main",
            "sentinel-openclaw=src.openclaw_isolation:main",
            "sentinel-setup=src.setup_wizard:main",
            "sentinel-status=src.status_dashboard:main",
            "sentinel-config=src.config_manager:main",
        ],
    },
)
