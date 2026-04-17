"""Configuration management for Gokow."""

from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class OPSECConfig(BaseModel):
    """OPSEC configuration."""
    stealth: bool = Field(default=False, description="Enable stealth mode")
    delays: Dict[str, float] = Field(default_factory=lambda: {'min': 1.0, 'max': 3.0})
    user_agent_rotation: bool = Field(default=True)
    custom_headers: Dict[str, str] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    """Configuration for scanning operations."""
    target: str = ""
    scan_type: str = "port"
    timeout: int = Field(default=5, ge=1, le=30)
    max_workers: int = Field(default=4, ge=1, le=20)
    output_format: str = Field(default="text", pattern="^(text|json|csv|markdown)$")
    output_file: Optional[str] = None
    verbose: bool = False
    aggressive: bool = False
    ports: str = "1-1000"
    opsec: OPSECConfig = Field(default_factory=OPSECConfig)


class GokowSettings(BaseSettings):
    """Main settings for Gokow."""
    app_name: str = "Gokow"
    version: str = "0.1.0"
    debug: bool = False
    default_config: ScanConfig = Field(default_factory=ScanConfig)

    class Config:
        env_prefix = "GOKOW_"
        env_file = ".env"
        env_file_encoding = "utf-8"

    @classmethod
    def from_file(cls, config_file: Path) -> "GokowSettings":
        """Load settings from YAML file."""
        import yaml
        with open(config_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def save_to_file(self, config_file: Path):
        """Save settings to YAML file."""
        import yaml
        data = self.dict()
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, indent=2)


# Global settings instance
settings = GokowSettings()