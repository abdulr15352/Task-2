from pydantic_settings import BaseSettings
from pydantic import SecretStr
from dotenv import load_dotenv

load_dotenv(".env")  # Load environment variables from a .env file if present


class Settings(BaseSettings):
    JWT_SECRET_KEY: SecretStr 
    JWT_ALGORITHM: str 
    JWT_EXPIRATION_MINUTES: int


    class Config:
        env_file = ".env" # Specify the .env file to load variables from
