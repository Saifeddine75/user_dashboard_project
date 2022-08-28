import os
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer

templates = Jinja2Templates(directory='templates')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
JWT_SECRET_KEY = os.getenv('JWT_TOKEN')

try:
    from .local_settings import *
except ImportError:
    # Should be local and DEBUG
    pass
