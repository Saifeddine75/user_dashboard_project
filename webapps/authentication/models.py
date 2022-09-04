# External import
from typing import Union
from passlib.hash import bcrypt
from typing import Optional, List

# FastAPI and related import
from pydantic import BaseModel
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise import fields
from tortoise.models import Model
from uuid import UUID, uuid4

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class Users(Model):
    """ Authentification user models with credentials

    Parameters
    ----------
    Model : Tortoise base class model
        Simplify ORM process

    Returns
    -------
    Class method
        Allow to get any user registered based on his username
    """
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)
    pseudo = fields.CharField(30)
    city = fields.CharField(30, default='', blank=True)
    disabled = fields.BooleanField(default=False)

    @classmethod
    async def get_user(cls, username):
        return cls.get(username=username)

    def verify_password(self, password):
        """ Verify password using password and password hash

        Parameters
        ----------
        password : str
            Password not hashed

        Returns
        -------
        Bool
            Password verification status
        """
        return bcrypt.verify(password, self.password_hash)


# Custom data types that represents what users have
Users_Pydantic = pydantic_model_creator(
    Users, name='User')

# Custom data types that represents what users can pass as input
UsersIn_Pydantic = pydantic_model_creator(
    Users, name='UserIn', exclude_readonly=True
)


class UserInDB(Users):
    hashed_password: str


# PUT
class UserUpdateRequest(BaseModel):
    """
    Update user class attributes
    """
    pseudo: Optional[str]
    password: Optional[str]
    city: Optional[str]
