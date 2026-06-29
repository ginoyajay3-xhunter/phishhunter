import os
import logging

# VirusTotal API key - set this as an environment variable, never hardcode it.
# On Linux/Mac:   export VT_API_KEY="your_key_here"
# On Windows:     set VT_API_KEY=your_key_here
VT_API_KEY = os.environ.get("VT_API_KEY", "")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Risk score thresholds
RISK_THRESHOLD_HIGH = 50
RISK_THRESHOLD_SUSPICIOUS = 25

# Centralized logger — every scanner module logs actual exceptions here
# instead of silently swallowing them into a generic "lookup failed"
# string. Set LOG_LEVEL=DEBUG in the environment for verbose output.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phish_dashboard")

