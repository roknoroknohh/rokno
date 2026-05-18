# rokno_a3 - Configuration Module
# Environment: Termux (Android) + Ubuntu
# Device: Samsung Galaxy A14 (arm64)

import os

# === System Constraints ===
MAX_ANALYSIS_TIME = 55
MAX_MEMORY_MB = 512
SINGLE_TARGET_ONLY = True

# === Tool Paths (Termux/Ubuntu) ===
TOOLS = {
    "whois": "whois",
    "whatweb": "whatweb",
    "httpx": "httpx",
    "gau": "gau",
    "assetfinder": "assetfinder",
    "linkfinder": "python3 /opt/LinkFinder/linkfinder.py",
}

# === Output Settings ===
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
TEMP_DIR = "/tmp/rokno_a3"

# === AI Settings ===
# Option 1: Gemini (needs API key)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-1.5-flash"

# Option 2: Free AI (no API key needed)
# Uses pollinations.ai - completely free, no registration
USE_FREE_AI = os.getenv("USE_FREE_AI", "true").lower() in ("true", "1", "yes")
FREE_AI_URL = "https://text.pollinations.ai"
FREE_AI_MODEL = "openai"  # options: openai, mistral, llama, etc.

# === Passive Data Only ===
PASSIVE_MODE = True
NO_EXPLOITATION = True
