import jwt

# Packages
from fastapi import FastAPI, APIRouter
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise.contrib.fastapi import register_tortoise
from passlib.hash import bcrypt

# Project models
from models import Users, Users_Pydantic, UsersIn_Pydantic

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

JWT_SECRET = 'jpoja"%%6())iip"jçu%2é"!!ué"z4d484s686q46q4dzjziç"uçu'


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


@app.post('/token')
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
    try:
        user = await authenticate_user(form_data.username, form_data.password)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User not found'
        )

    # Create new user with credentials: username and hashed password
    user_obj = await Users_Pydantic.from_tortoise_orm(user)

    # *** To improve security: Don't show password hash in the payload
    # Hash it another time to produce a secure access token
    user_obj_safe = {}
    user_obj_safe = user_obj.dict()
    user_obj_safe['password_hash'] = bcrypt.hash(user_obj.dict['password_hash'])
    token = jwt.encode(user_obj_safe, JWT_SECRET)
    
    return {'access_token': token, 'token_type': 'bearer' }


@app.get("/")
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
    

@app.post('/users', response_model=Users_Pydantic)
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
    user_obj = Users(
        username=user.username,
        password_hash=bcrypt.hash(user.password_hash)
    )
    await user_obj.save()
    return await Users_Pydantic.from_tortoise_orm(user_obj)


@app.get('/users/me', response_model=Users_Pydantic)
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

register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['models']},
    generate_schemas=True,  # Create Table if it not exist
    add_exception_handlers=True,
)
