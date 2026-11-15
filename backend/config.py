import os
import configparser
from pathlib import Path
from typing import Optional, Dict, Tuple
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

REGIONS = {
    "us": "api.veracode.com",
    "eu": "api.veracode.eu",
    "us-gov": "api.veracode.us",
}

class Settings:
    def __init__(self):
        self.region: str = os.getenv("VERACODE_REGION", "us").lower()
        self.host: str = REGIONS.get(self.region, "api.veracode.com")
        self.base_url: str = f"https://{self.host}"
        self.server_host: str = os.getenv("SERVER_HOST", "127.0.0.1")
        self.server_port: int = int(os.getenv("SERVER_PORT", "8000"))
        self.mock_mode: bool = os.getenv("VERACODE_MOCK_MODE", "false").lower() in ("true", "1", "yes")
        
        # In-memory session credentials (can be set via UI securely in memory only)
        self._session_api_id: Optional[str] = None
        self._session_api_secret: Optional[str] = None
        self._session_region: Optional[str] = None

    def get_credentials(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Retrieves Veracode credentials securely in priority order:
        1. Explicit in-memory session credentials (passed via UI for testing)
        2. Environment variables (VERACODE_API_KEY_ID, VERACODE_API_KEY_SECRET)
        3. ~/.veracode/credentials file (default Veracode profile)
        """
        # 1. In-memory session
        if self._session_api_id and self._session_api_secret:
            return self._session_api_id.strip(), self._session_api_secret.strip()

        # 2. Environment variables
        api_id = os.getenv("VERACODE_API_KEY_ID")
        api_secret = os.getenv("VERACODE_API_KEY_SECRET")
        if api_id and api_secret:
            return api_id.strip(), api_secret.strip()

        # 3. ~/.veracode/credentials
        try:
            creds_path = Path.home() / ".veracode" / "credentials"
            if creds_path.exists():
                config = configparser.ConfigParser()
                config.read(creds_path)
                profile = os.getenv("VERACODE_PROFILE", "default")
                if profile in config:
                    c_id = config[profile].get("veracode_api_key_id")
                    c_secret = config[profile].get("veracode_api_key_secret")
                    if c_id and c_secret:
                        return c_id.strip(), c_secret.strip()
        except Exception:
            pass

        return None, None

    def set_session_credentials(self, api_id: str, api_secret: str, region: Optional[str] = None):
        """Set in-memory credentials without persisting to disk."""
        self._session_api_id = api_id.strip() if api_id else None
        self._session_api_secret = api_secret.strip() if api_secret else None
        if region and region.lower() in REGIONS:
            self.set_region(region.lower())

    def clear_session_credentials(self):
        """Clear in-memory session credentials."""
        self._session_api_id = None
        self._session_api_secret = None

    def set_region(self, region: str):
        if region.lower() in REGIONS:
            self.region = region.lower()
            self.host = REGIONS[self.region]
            self.base_url = f"https://{self.host}"

    def get_status(self) -> Dict:
        """Returns safe status dictionary with masked credentials."""
        api_id, api_secret = self.get_credentials()
        has_creds = bool(api_id and api_secret)
        
        masked_id = None
        if api_id:
            masked_id = f"{api_id[:4]}...{api_id[-4:]}" if len(api_id) > 8 else "****"

        return {
            "is_configured": has_creds,
            "masked_api_id": masked_id,
            "region": self.region,
            "host": self.host,
            "mock_mode": self.mock_mode or not has_creds,
            "has_credentials": has_creds
        }

settings = Settings()
