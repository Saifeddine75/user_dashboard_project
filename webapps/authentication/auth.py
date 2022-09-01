# Packages import
import os
import jwt
from datetime import datetime, timedelta
from passlib.hash import bcrypt
from sqlalchemy.exc import IntegrityError

# FastAPI framework import
from fastapi import HTTPException, status
from fastapi import APIRouter, Request, Form, Depends
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

# App import
from settings import oauth2_scheme, JWT_SECRET_KEY
from settings import templates, CustomURLProcessor
from .utils.auth_tools import generate_token, authenticate_user
from .utils.auth_tools import get_current_active_user
from .models import Users, Users_Pydantic, UsersIn_Pydantic
from .models import Token
from .forms import RegistrationValidationForm


JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
print(JWT_SECRET_KEY)

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
async def index(token: str = Depends(oauth2_scheme)):
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
    return {'the_token': token}


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


@router.get('/users/me', response_model=Users_Pydantic)
async def read_users_me(current_user: Users_Pydantic = Depends(get_current_active_user)):
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


@router.post('/login')
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
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

    form = await request.form()
    print(form.keys())

    print('GENERATE TOKEN')
    generate_token(form_data)


    # context = {
    #     'request': request,
    #     'user': user
    # }

    # return templates.TemplateResponse('index.html', context)

@router.post('/token', response_model=Token)
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
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
    # user = await authenticate_user(form_data.username, form_data.password)

    # if not user:
    #     return {'error': 'invalid credentials'}

    # user_obj_safe = {}
    username = 'saif@admin.com'
    password = 'Test92600%'
    # username = form_data.username
    # password = form_data.password

    try:
        print('form', username, password)
        user = await authenticate_user(username, password)
    except Exception as exc:
        print('exception', exc)
        return {'error': 'failed to authenticate user'}

    # Create new user with credentials: username and hashed password
    user_obj = await Users_Pydantic.from_tortoise_orm(user)

    # Hash it 10 times to produce a more secure access token
    print('OK')
    ph = user_obj.password_hash
    for _ in range(10):
        ph = bcrypt.hash(ph)
    user_obj.password_hash = str(ph)

    token = jwt.encode(user_obj.dict(), JWT_SECRET_KEY)

    return {'access_token': token, 'token_type': 'bearer'}