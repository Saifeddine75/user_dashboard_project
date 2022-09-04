import os
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from fastapi import Request


templates = Jinja2Templates(directory='templates')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# class CustomURLProcessor:
#     def __init__(self):
#         self.path = ""
#         self.request = None

#     def url_for(self, request: Request, name: str, **params: str):
#         self.path = request.url_for(name, **params)
#         self.request = request
#         return self


# Following is not working in fastapi
try:
    from .local_settings import *
except ImportError:
    # Should be local and DEBUG
    pass

from dotenv import load_dotenv

load_dotenv(".env")

JWT_SECRET_KEY = os.environ["SECRET_KEY"]

