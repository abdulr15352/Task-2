class Endpoints:
    ROOT = "/"
    HEALTH = "/health"
    REGISTER = "/register"
    LOGIN = "/login"
    UserInfo = "/info"
    DELETE = "/delete"



class ResponseMessages:
    WELCOME = "Welcome to the Voting App!"
    HEALTHY = "The service is healthy"
    USER_CREATED = "User created successfully"
    USER_LOGGED_IN = "User logged in successfully"
    USER_ALREADY_EXISTS = "User with this email already exists"
    USER_NOT_FOUND = "User not found"
    INVALID_CREDENTIALS = "Invalid email or password"
    INVALID_TOKEN_MISSING_EMAIL = "Invalid token: email missing"
    INVALID_TOKEN = "Invalid token"
    EXPIRED_TOKEN = "Token has expired"
    USER_DELETED = "User deleted successfully"
    