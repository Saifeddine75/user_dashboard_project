# FastAPI import
from fastapi import APIRouter, Request, Form
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

# My FastAPI models
from webapps.authentication.models import Users, Users_Pydantic, UsersIn_Pydantic
from webapps.authentication.utils.form_tools import RegistrationValidationForm
from settings import templates

router = APIRouter(tags=['authentication'])

### USER LOGIN
@router.get('/login')
async def login(request: Request):

    context = {'request': request}

    return templates.TemplateResponse('authentication/login.html', context)


@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
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

