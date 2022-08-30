# Packages import
import jwt
from passlib.hash import bcrypt
from sqlalchemy.exc import IntegrityError

# FastAPI framework import
from fastapi import HTTPException, status
from fastapi import APIRouter, Request, Form, Depends
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

# Settings import
from settings import oauth2_scheme, templates, JWT_SECRET_KEY

# Functions import
from .utils.auth_tools import get_current_active_user, generate_token
from .forms import RegistrationValidationForm

# Models import
from .models import Users, Users_Pydantic, UsersIn_Pydantic


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
#                        LOGIN                           #
##########################################################

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


@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """ Login user and create his access token

    Parameters
    ----------
    form_data : OAuth2PasswordRequestForm, optional
        Form login provided by fastapi.security package, by default Depends()

    Returns
    -------
    _type_
        _description_

    Raises
    ------
    HTTPException
        _description_
    """
    assert True!=True
    print('form_data', form_data)
    user = Users.get(username=form_data.username)
    if not user:
        raise HTTPException(
            status_code=400, detail="Incorrect username or password")

    print('credentials safe', user.username, user.password)

    token = await generate_token(
        username=user.username,
        password_hash=user.password
    )
    print('token', token)

    return token
    # return {"access_token": user.username, "token_type": "bearer"}



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
        errors = form.errors()
        errors = {k: v for k, v in errors.items() if v}
        
        context = {
            'request': request,
            'errors': errors,
            'is_valid': False
        }

    else:
        username = form.get('username')
        password = form.get('password')

        errors = []

        try:
            if not Users.get(username=username):
                user = await create_user(
                    UsersIn_Pydantic(
                        username=username,
                        password_hash=password
                    )
                )
            else:
                errors.append('This username is already used!')


        except IntegrityError:
            errors.append('This email is already registered')

        except Exception as exc:
            errors.append(str(exc))
        
        print('errors', errors)
        is_valid = False if errors else True

        context = {
            'request': request,
            'is_valid': is_valid
        }

    return templates.TemplateResponse('authentication/register.html', context)
