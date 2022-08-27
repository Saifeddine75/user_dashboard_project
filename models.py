from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise import fields
from tortoise.models import Model
from passlib.hash import bcrypt
from uuid import UUID, uuid4

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
    username = fields.CharField(50)
    password_hash = fields.CharField(128)
    
    @classmethod
    async def get_user(cls, username):
        return cls.get(username=username)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


# Custom data types that represents what users have
Users_Pydantic = pydantic_model_creator(Users, name='User')

# Custom data types that represents what users can pass as input
UsersIn_Pydantic = pydantic_model_creator(
    Users, name='UserIn', exclude_readonly=True
)
