import os
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from fastapi import Request

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

templates = Jinja2Templates(directory='templates')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


class CustomURLProcessor:
    def __init__(self):
        self.path = ""
        self.request = None

    def url_for(self, request: Request, name: str, **params: str):
        self.path = request.url_for(name, **params)
        self.request = request
        return self


# Following is not working 
try:
    from .local_settings import *
except ImportError:
    # Should be local and DEBUG
    pass

os.environ['JWT_SECRET_KEY'] = 'jpoja"TF6())iip"SMQaWjXVTUçu%2é"!!ué"z4d454z86431sSD4s686qzXXSz46qodkpoe687z;ùxs5334q4dzjziç"uçu'
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
print('JWT_SECRET_KEY', JWT_SECRET_KEY)
