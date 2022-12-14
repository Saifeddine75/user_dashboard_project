# External import
import os
import jwt
from passlib.hash import bcrypt
from jose import JWTError

# FastAPI import
from fastapi import Form
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

# My FastAPI models
from webapps.authentication.models import Users, Users_Pydantic, UsersIn_Pydantic
from webapps.authentication.models import TokenData
from settings import oauth2_scheme, JWT_SECRET_KEY, ALGORITHM


async def authenticate_user(username: str, password: str):
    """ Authenticate a user with his username and his hash password decrypted

    Parameters
    ----------verify_password
    username : str, 
        Account username used in registration form
    password : str, 
        Account hash password used in registration form

    Returns
    -------
    Users instance, 
        Users instance of authenticated user
    """
    user = await Users.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """ Get current user authenticated by decrypting the encrypted access token
    
    This function should be used in every endpoint that need authentification
    control

    Parameters
    ----------
    token : str, optional, 
        Encrypted access token, by default Depends(oauth2_scheme)

    Returns
    -------
    Users model instance, 
        User model with attributes registered: id, username, password_hash

    Raises
    ------
    HTTPException, 
        If payload could not be decrypted successfully return 401 Unauthorized Error
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = Users.get_user(username=token_data.username)
    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(current_user: Users_Pydantic = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

