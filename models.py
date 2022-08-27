from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise import fields
from tortoise.models import Model


class Users(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50)
    password_hash = fields.CharField(128)
    
    @classmethod
    async def get_user(cls, username):
        return cls.get(username=username)

    def verify_password(self, password):
        return True

