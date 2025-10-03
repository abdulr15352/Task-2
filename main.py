from fastapi import FastAPI, status
from utils.constants import Endpoints, ResponseMessages
import uvicorn
from v1.users.UserEndpoints import UserRouter, AdminRouter
from logger import get_logger

logger = get_logger()

# Making an instance of FastAPI as voting_app
voting_app = FastAPI(
    title="Voting API",
    description="API for voting application",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


voting_app.include_router(UserRouter)
voting_app.include_router(AdminRouter)
logger.info("User router has been included.")

@voting_app.get(Endpoints.ROOT)
def read_root():
    """
    Root endpoint returning a welcome message.
    """
    return {"message": ResponseMessages.WELCOME, "status": status.HTTP_200_OK}

@voting_app.get(Endpoints.HEALTH)
def read_health():
    return {"message": ResponseMessages.HEALTHY, "status": status.HTTP_200_OK}

logger.info("Health check endpoint is set up.")
logger.info("Application setup is complete. Starting the server...")