"""
Veracode Sandbox Vulnerability & Metrics Tracker Launcher.
Usage:
    py run.py
"""
import sys
import uvicorn
from backend.config import settings

def main():
    print("=" * 70)
    print("  VERACODE SANDBOX VULNERABILITY & METRICS TRACKER")
    print("  Enterprise Full-Stack Security & Tool Integration")
    print("=" * 70)
    
    status = settings.get_status()
    if status["is_configured"]:
        print(f"[*] Veracode Credentials: CONFIGURED (API ID: {status['masked_api_id']})")
        print(f"[*] Target Region: {status['region'].upper()} ({status['host']})")
    else:
        print("[!] Veracode Credentials: NOT CONFIGURED")
        print("[*] Running in: INTERACTIVE DEMO / SIMULATION MODE")
        print("    (You can connect live Veracode credentials at any time in the UI)")

    print(f"[*] Web Server URL: http://{settings.server_host}:{settings.server_port}")
    print("=" * 70)

    uvicorn.run(
        "backend.main:app",
        host=settings.server_host,
        port=settings.server_port,
        reload=False,
        log_level="info"
    )

if __name__ == "__main__":
    main()
