# External import
import jwt
from passlib.hash import bcrypt
from sqlalchemy.exc import IntegrityError

# FastAPI import
from fastapi import APIRouter
from fastapi import Request, Form, Depends
from fastapi import HTTPException, status

from .routes import register, login

# My FastAPI models
from .models import Users, Users_Pydantic, UsersIn_Pydantic
from webapps.authentication.utils.form_tools import RegistrationValidationForm
from webapps.authentication.utils.auth_tools import get_current_active_user
from settings import oauth2_scheme, templates

router = APIRouter(tags=['authentication'])
router.add_api_route('/register/', register.register, methods=['GET'])
router.add_api_route('/register/', register.register, response_model=Users_Pydantic, methods=['POST'])
router.add_api_route('/login/', login.login, methods=['GET'])
router.add_api_route('/login/', login.login, methods=['POST'])


# *** Imrove security: Hide it in os.env
JWT_SECRET = 'jpoja"%%6())iip"jçu%2é"!!ué"z4d484s686q46q4dzjziç"uçu'


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


@router.get('/users/me', response_model=Users_Pydantic)
async def read_users_me(current_user: Users_Pydantic = Depends(get_current_active_user)):
    return current_user


