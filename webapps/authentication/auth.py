# External import
import jwt
from passlib.hash import bcrypt
from sqlalchemy.exc import IntegrityError

# FastAPI import
from fastapi import APIRouter, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from .routes import register, login

# My FastAPI models
from .models import Users, Users_Pydantic, UsersIn_Pydantic
from webapps.authentication.utils.form_tools import RegistrationValidationForm


router = APIRouter(tags=['authentication'])
router.add_api_route('/register/', register.register, methods=['GET'])
router.add_api_route('/login/', login.login, methods=['GET'])

templates = Jinja2Templates(directory='templates')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

# *** Imrove security: Hide it in os.env
JWT_SECRET = 'jpoja"%%6())iip"jçu%2é"!!ué"z4d484s686q46q4dzjziç"uçu'

### USER LOGIN
@router.get('/login')
async def login(request: Request):

    context = {'request': request}

    return templates.TemplateResponse('authentication/login.html', context)


@router.post('/login')
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = query_user(email)
    if not user:
        # you can return any response or error of your choice
        raise InvalidCredentialsException
    elif password != user['password']:
        raise InvalidCredentialsException
    try:
        user = await authenticate_user(form_data.username, form_data.password)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='User not found'
        )
    context = {'request': request}

    return templates.TemplateResponse('authentication/login.html', context)

### USER REGISTRATION

@router.get('/register')
async def register(request: Request):

    context = {'request': request}

    return templates.TemplateResponse('authentication/register.html', context)


@router.post('/register', response_model=Users_Pydantic)
async def register(request: Request):

    form = await request.form()
    form = RegistrationValidationForm.get_valid_form(form)

    if not form.is_valid:
        errors = form.form_errors
        print(errors)
        context = {
            'request': request,
            'errors': errors
        }

    else:
        errors = []
        assert isinstance(form.username, str)
        assert isinstance(form.password, str)

        # print('form', form)

        try:
            user = await create_user(
                UsersIn_Pydantic(
                    username=form.get('username'),
                    password_hash=form.get('password')
                )
            )
            u = Users.get(username=form.username)
            print('credentials safe', user.username, user.password)

            token = await generate_token(
                username=u.username,
                password_hash=u.password
            )
            print('token', token)

        except IntegrityError:
            errors.append('Email already registered')

        except Exception as exc:
            # raise HTTPException(
            #     status_code=status.HTTP_401_UNAUTHORIZED,
            #     detail='User not found'
            # )
            print(exc)
            errors.append(str(exc))

        context = {'request': request}

    return templates.TemplateResponse('authentication/register.html', context)


async def authenticate_user(username: str, password: str):
    """ Authenticate a user with his credentials

    Parameters
    ----------
    username : str, 
        Account username used in registration form
    password : str, 
        Account password used in registration form

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


@router.post('/token')
async def generate_token(username: str, password: str):
# async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
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
    try:
        print('form', username, password)
        user = await authenticate_user(username, password)
    except Exception as exc:
        return {'error': 'failed to authenticated user'}
        # raise HTTPException(
        #     status_code=status.HTTP_404_NOT_FOUND,
        #     detail='User not found'
        # )

    # Create new user with credentials: username and hashed password
    user_obj = await Users_Pydantic.from_tortoise_orm(user)

    # *** To improve security: Don't show password hash in the payload
    # Hash it another time to produce a secure access token
    user_obj_safe = {}
    user_obj_safe = user_obj.dict()
    for _ in range(10):
        user_obj_safe['password_hash'] = bcrypt.hash(
            user_obj_safe['password_hash'])
        print(user_obj_safe['password_hash'])
    token = jwt.encode(user_obj_safe, JWT_SECRET)

    return {'access_token': token, 'token_type': 'bearer'}


@router.get("/")
async def index(token: str = Depends(oauth2_scheme)):
    """ API root path

    Parameters
    ----------
    token : str, optional, 
        User access token, by default Depends(oauth2_scheme)

    Returns
    -------
    token, 
        Encrypted access token with JWT_SECRET value
    """
    return {'the_token': token}


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
    try:
        # decode the token
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await Users.get(id=payload.get('id'))

    except Exception as exc:
        print('Exception', exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )

    return await Users_Pydantic.from_tortoise_orm(user)


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
    user_obj = Users(username=user.username, password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await Users_Pydantic.from_tortoise_orm(user_obj)


@router.get('/users/me', response_model=Users_Pydantic)
async def get_user(user: Users_Pydantic = Depends(get_current_user)):
    """ Get user authenticated by calling get_current_user function

    Parameters
    ----------
    user : Users_Pydantic, optional
        User with username and hashed password, by default Depends(get_current_user)

    Returns
    -------
    Users instance
        User with username and hashed password registered in database
    """
    return user
