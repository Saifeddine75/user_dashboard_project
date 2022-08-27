# External Packages import
import uvicorn
import jwt
from passlib.hash import bcrypt
from uuid import UUID

# FastAPI library import
from fastapi import FastAPI, APIRouter
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise.contrib.fastapi import register_tortoise

# FastAPI models import
from models import Users, Users_Pydantic, UsersIn_Pydantic

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

JWT_SECRET = 'jpoja"%%6())iip"jçu%2é"!!ué"z4d484s686q46q4dzjziç"uçu'


async def authenticate_user(email: str, password: str):
    """ Authenticate a user with his credentials

    Parameters
    ----------
    email : str, 
        Account email used in registration form
    password : str, 
        Account password used in registration form

    Returns
    -------
    Users instance, 
        Users instance of authenticated user
    """
    user = await Users.get(email=email)
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
    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
        return {'error': 'invalid credentials'}
    
    print("authentification : OK")
    # Create new user with credentials: email and hashed password
    user_obj = await Users_Pydantic.from_tortoise_orm(user)
    print("user instanciation : OK")

    # To improve security: Remove password hash from the payload
    # (modify user_obj.dict())
    # print(user_obj.dict().pop('password_hash'))
    # print('dict without password_hash', user_obj.dict())
    # token = jwt.encode(user_obj.dict().pop('password_hash'), JWT_SECRET)
    token = jwt.encode(user_obj.dict(), JWT_SECRET)
    print("token encoding : OK")

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
        User model with attributes registered: id, email, password_hash

    Raises
    ------
    HTTPException, 
        If payload could not be decrypted successfully return 401 Unauthorized Error
    """
    try:
        # decode the token
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await Users.get(uid=payload.get('uid'))

    except Exception as exc:
        print('Exception', exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password'
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
        User instance with input credentials, email and hashed password
    """
    print("create user ...")

    user_obj = Users(
        email=user.email,
        password_hash=bcrypt.hash(user.password_hash),
    )
    print("User creation: OK")

    if user_obj.verify_email():
        await user_obj.save()
        return await Users_Pydantic.from_tortoise_orm(user_obj)
        print("User save: OK")

    else:
        print("ERROR")
        raise HTTPException(
            status_code=401,
            detail=f'Identifiant have to an email'
        )

@app.get('/users/me', response_model=Users_Pydantic)
async def get_user(user: Users_Pydantic = Depends(get_current_user)):
    """ Get user authenticated by calling get_current_user function

    Parameters
    ----------
    user : Users_Pydantic, optional
        User with email and hashed password, by default Depends(get_current_user)

    Returns
    -------
    Users instance
        User with email and hashed password registered in database
    """
    return user


@app.delete('/users/{user_uid}')
async def delete_user(user_uid: UUID):
    user = await Users.get(uid=user_uid)
    if user.uid == user_uid:
        user.delete()
        return

    raise HTTPException(
        status_code=404,
        detail=f'user with id: "{user_uid}" does not exists'
    )


@app.put("/users/{user_id}")
async def update_user(user_update: UsersIn_Pydantic, user_uid: UUID):
    user_list = await Users.all()
    for user in user_list:
        if user.uid == user_uid:
            if user_update.email is not None:
                user.email = user_update.email
            return

    raise HTTPException(
        status_code=404,
        detail=f'user with id "{user_uid}" does not exists'
    )


register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['models']},
    generate_schemas=True,  # Create Table if it not exist
    add_exception_handlers=True,
)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
