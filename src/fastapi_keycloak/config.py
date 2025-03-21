from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    KEYCLOAK_SERVER_URL: str
    KEYCLOAK_REALM: str
    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str
    ALGORITHM: str = "RS256"

    class Config():
        env_file = ".env"


settings = Settings()
