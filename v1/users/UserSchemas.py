from pydantic import BaseModel, EmailStr, SecretStr
from typing import Optional

class UserSchema(BaseModel):
    name: str
    email: EmailStr
    password: SecretStr
    is_active: bool = True


class UserRegisterResponseSchema(BaseModel):
    id: int
    name: str
    email: EmailStr
    is_active: bool

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: SecretStr

