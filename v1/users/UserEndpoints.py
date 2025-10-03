from fastapi import APIRouter, status, HTTPException, Request, Depends
from fastapi.security import OAuth2PasswordBearer
from utils.constants import Endpoints, ResponseMessages
from utils.security import hash_password, verify_password, create_access_token, decode_access_token
from .UserSchemas import UserSchema, UserLoginSchema, UserRegisterResponseSchema
from .UserDBModels import UserDBModel, add_user, get_user_by_email, delete_user_by_id


UserRouter = APIRouter(prefix="/users", tags=["Users"])
AdminRouter = APIRouter(prefix="/admin", tags=["Admin"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=Endpoints.LOGIN)

@UserRouter.post(Endpoints.REGISTER, status_code=status.HTTP_201_CREATED, response_model=UserRegisterResponseSchema)
def create_user(user: UserSchema):
    """
    Endpoint to create a new user.
    """
    # validate user
    existing_user = get_user_by_email(user.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ResponseMessages.USER_ALREADY_EXISTS)
    # add user to the database
    hashed_password = hash_password(user.password)
    new_user = UserDBModel(**user.model_dump(exclude={"password"}), hashed_password=hashed_password)
    add_user(new_user)
    return new_user



@UserRouter.get(Endpoints.LOGIN)
def login_user(user: UserLoginSchema):
    """
    Endpoint to log in a user.
    """
    # validate user
    existing_user = get_user_by_email(user.email)
    if not existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ResponseMessages.USER_NOT_FOUND)

    # verify password
    if not verify_password(user.password, existing_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=ResponseMessages.INVALID_CREDENTIALS)
    # Generate JWT token
    payload = {
        "user_id": existing_user.id,
        "email": existing_user.email}
    token = create_access_token(data=payload)
    return {"message": ResponseMessages.USER_LOGGED_IN, "token": token, "authentication_type" :"Bearer"}




@UserRouter.get(Endpoints.UserInfo)
def get_user_info(payload = Depends(decode_access_token)):
    """
    Endpoint to get user information.
    """
    return payload

@UserRouter.delete(Endpoints.DELETE)
def delete_user(payload = Depends(decode_access_token)):
    """
    Endpoint to delete a user.
    """
    user_id = payload.get("user_id")
    from .UserDBModels import UsersDB
    user = UsersDB.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ResponseMessages.USER_NOT_FOUND)
    delete_user_by_id(user_id)
    return {"message": ResponseMessages.USER_DELETED, "status": status.HTTP_200_OK}


