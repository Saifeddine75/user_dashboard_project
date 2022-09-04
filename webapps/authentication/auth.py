# Packages import
import os
import jwt
from datetime import datetime, timedelta
from passlib.hash import bcrypt
from sqlalchemy.exc import IntegrityError
from typing import Union

# FastAPI framework import
from fastapi import HTTPException, status
from fastapi import APIRouter, Request, Form, Depends
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse

# App import
from settings import oauth2_scheme
from settings import ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from settings import templates
from .utils.auth_tools import authenticate_user
from .utils.auth_tools import get_current_active_user, get_current_user # test
from .models import Users, Users_Pydantic, UsersIn_Pydantic, UserUpdateRequest
from .models import Token
from .forms import RegistrationValidationForm

JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')

# templates.env.globals['CustomURLProcessor'] = CustomURLProcessor
router = APIRouter(tags=['authentication'])


# TODO: fix different behavior to refactor, for now don't use refactored routes
# from .routes import register, login
# router.add_api_route('/register/', register.register, methods=['GET'])
# router.add_api_route('/register/', register.register, response_model=Users_Pydantic, methods=['POST'])
# router.add_api_route('/login/', login.login, methods=['GET'])
# router.add_api_route('/login/', login.login, methods=['POST'])


### ROOT
@router.get("/")
async def index(current_user: Users_Pydantic = Depends(get_current_active_user)):
    """ API Root Path

    Parameters
    ----------
    token : str, optional, 
        User access token provided by the OAuth2PasswordBearer instance, by default Depends(oauth2_scheme)

    Returns
    -------
    token, 
        Encrypted access token with JWT_SECRET value
    """
    print('OK')
    print('user', current_user)
    context = {
        'user': current_user
    }
    return templates.TemplateResponse('/index.html', context)

    # return {'the_token': token}


##########################################################
#                        REGISTER                        #
##########################################################

### CREATE USER AND HASH HIS PASSWORD
@router.post('/users', response_model=Users_Pydantic)
async def create_user(user: UsersIn_Pydantic):
    """ Create user with UserIn_Pydantic attributes

    Parameters
    ----------
    user : UsersIn_Pydantic, 
        User instance without read-only attributes

    Returns
    -------
    Users instance, 
        User instance with input credentials, username and hashed password
    """
    user_obj = Users(username=user.username,
                     password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await Users_Pydantic.from_tortoise_orm(user_obj)


@router.get('/register')
async def register(request: Request):

    context = {'request': request}

    return templates.TemplateResponse('authentication/register.html', context)


@router.post('/register', response_model=Users_Pydantic)
async def register(request: Request):

    form = await request.form()
    form = RegistrationValidationForm.get_valid_form(form)

    if not form.is_valid:
        form_errors = form.errors()

    else:
        form_errors = {}
        errors = []

        username = form.get('username')
        password = form.get('password')

        try:
            user = await create_user(
                UsersIn_Pydantic(
                    username=username,
                    password_hash=password,
                    city='',
                    disabled=False,  # For test
                )
            )

        except Exception as exc:
            if 'UNIQUE constraint failed' in str(exc):
                errors.append('This email is already registered!')
            else:
                errors.append(str(exc))

        form_errors['submission'] = errors

    errors = {k: v for k, v in form_errors.items() if v}
    print(len(errors))
    is_valid = True if len(errors)==0 else False

    context = {
        'request': request,
        'errors': errors,
        'is_valid': is_valid
    }

    return templates.TemplateResponse('authentication/register.html', context)


##########################################################
#                        LOGIN                           #
##########################################################


@router.post('/users/me', response_model=Users_Pydantic)
async def read_users_me(current_user: Users_Pydantic = Depends(get_current_user)):
    """ Get current user through auth payload decoding

    Parameters
    ----------
    current_user : Users_Pydantic, optional
        User get through "get_current_active_user function", by default Depends(get_current_active_user)

    Returns
    -------
    Users_Pydantic instance
        Return Users_Pydantic instance of actual user 
        (This Pydantic model allow to hide read-only fields)
    """
    return current_user


@router.get('/login')
async def login(request: Request):
    """ Get login page with form

    Parameters
    ----------
    request : Request
        Get Request content 

    Returns
    -------
    TemplateResponse
        Return login template with form
    """

    context = {'request': request}

    return templates.TemplateResponse('authentication/login.html', context)

# def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    # to_encode = data.copy()
    # if expires_delta:
    #     expire = datetime.utcnow() + expires_delta
    # else:
    #     expire = datetime.utcnow() + timedelta(minutes=15)
    # to_encode.update({"exp": expire})

    # encoded_jwt = jwt.encode(user_obj.dict(), JWT_SECRET_KEY)
    encoded_jwt = jwt.encode(data, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@router.post('/login')
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """ Generate when user is authenticated

    Parameters
    ----------
    form_data : OAuth2PasswordRequestForm, optional, 
        Login Form that are used in this endpoint, by default Depends()

    Returns
    -------
    string, 
        User access token value and type
    """
    user = await authenticate_user(form_data.username, form_data.password)
    user_obj = None

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        # Create new user with credentials: username and hashed password
        user_obj = await Users_Pydantic.from_tortoise_orm(user)
        

    context = {
        'request': Request,
        'user': user_obj
    }

    return context


@router.get('/profile')
async def profile(request: Request):

    context = {'request': request}

    return templates.TemplateResponse('authentication/profile.html', context)


@router.post('/profile', response_model=Users_Pydantic)
async def profile(request: Request, user_update: UserUpdateRequest):

    form = await request.form()
    form = RegistrationValidationForm.get_valid_form(form)

    if not form.is_valid:
        form_errors = form.errors()

    else:
        form_errors = {}
        errors = []

        username = form.get('username')
        password = form.get('password')

        try:
            # Update user profile
            user = Users.get_user(username=username)
            if user_update.pseudo is not None:
                user.pseudo = user_update.pseudo
            if user_update.password is not None:
                user.password = user_update.password
            if user_update.city is not None:
                user.city=user_update.city


        except Exception as exc:
            if 'UNIQUE constraint failed' in str(exc):
                errors.append('This email is already registered!')
            else:
                errors.append(str(exc))

        form_errors['submission'] = errors

    errors = {k: v for k, v in form_errors.items() if v}
    print(len(errors))
    is_valid = True if len(errors) == 0 else False

    context = {
        'request': request,
        'errors': errors,
        'is_valid': is_valid
    }

    return templates.TemplateResponse('authentication/profile.html', context)


