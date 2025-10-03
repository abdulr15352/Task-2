from pydantic import BaseModel, EmailStr
from typing import Optional

class UserDBModel(BaseModel):
    id: int = 0
    name: str
    email: EmailStr
    hashed_password: str
    is_active: bool = True

# Key: uid, value: UserDBModel, create empty dictionary to simulate a database
UsersDB = {}

def get_next_user_id():
    """
    Get the next user ID for a new user.
    """
    if UsersDB:
        return max(UsersDB.keys()) + 1
    return 1

def get_user_by_email(email: str):
    """
    Retrieve a user from the database by their email.
    """
    return next((user for user in UsersDB.values() if user.email == email), None)

def add_user(user: UserDBModel):
    """
    Add a new user to the database.
    """
    user.id = get_next_user_id()
    UsersDB[user.id] = user
    return user

def delete_user_by_id(user_id: int):
    """
    Delete a user from the database by their ID.
    """
    return UsersDB.pop(user_id, None)







