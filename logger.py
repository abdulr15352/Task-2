import logging

# Configure the logging settings
logging.basicConfig(
    filename="logs/logs.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Function to get a configured logger
def get_logger(name: str = "voting_app_logger") -> logging.Logger:
    return logging.getLogger(name)
