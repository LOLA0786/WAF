import os
from typing import Dict, List, Optional
from pydantic import BaseSettings, validator
from enum import Enum

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class Settings(BaseSettings):
    # Application
    app_name: str = "WAF Optimization Platform"
    app_version: str = "3.0.0"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    
    # API
    api_prefix: str = "/api/v1"
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    
    # Security
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Database
    database_url: str = "sqlite:///./waf_platform.db"
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    
    # External APIs
    openai_api_key: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    
    # Rate Limiting
    rate_limit_per_hour: int = 1000
    rate_limit_per_day: int = 10000
    
    # Logging
    log_level: LogLevel = LogLevel.INFO
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Monitoring
    enable_metrics: bool = True
    metrics_port: int = 9090
    
    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    @validator("environment", pre=True)
    def validate_environment(cls, v):
        if isinstance(v, str):
            return Environment(v.lower())
        return v

# Global settings instance
settings = Settings()

class DatabaseConfig:
    def __init__(self):
        self.url = settings.database_url
        self.echo = settings.debug
    
    def get_engine_config(self) -> Dict:
        return {
            "url": self.url,
            "echo": self.echo,
            "pool_pre_ping": True,
            "pool_recycle": 300,
        }

class RedisConfig:
    def __init__(self):
        self.url = settings.redis_url
        self.encoding = "utf-8"
        self.decode_responses = True
    
    def get_connection_config(self) -> Dict:
        return {
            "host": "localhost",
            "port": 6379,
            "db": 0,
            "password": None,
        }

class LoggingConfig:
    def __init__(self):
        self.level = settings.log_level.value.upper()
        self.format = settings.log_format
    
    def get_config(self) -> Dict:
        return {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": self.format,
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                }
            },
            "handlers": {
                "default": {
                    "level": self.level,
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stdout",
                }
            },
            "loggers": {
                "waf_platform": {
                    "level": self.level,
                    "handlers": ["default"],
                    "propagate": False,
                }
            },
        }

# Global config instances
db_config = DatabaseConfig()
redis_config = RedisConfig()
logging_config = LoggingConfig()
