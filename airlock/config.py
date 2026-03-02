from pydantic_settings import BaseSettings


class AirlockConfig(BaseSettings):
    """Global configuration for the Airlock service."""

    model_config = {"env_prefix": "AIRLOCK_"}

    host: str = "0.0.0.0"
    port: int = 8000
    session_ttl: int = 180
    heartbeat_ttl: int = 60
    lancedb_path: str = "./data/reputation.lance"
    litellm_model: str = "ollama/llama3"
    litellm_api_base: str = "http://localhost:11434"
    protocol_version: str = "0.1.0"
