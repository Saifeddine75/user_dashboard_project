# Packages
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise.contrib.fastapi import register_tortoise

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

@app.get("/")
async def index(token: str = Depends(oauth2_scheme)):
    return {'the_token': token}

# Simple Authentification
@app.post('/token')
# Depends means return can be a form or nothing
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    return {'access_token': form_data.username + 'token'}


register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['models']},
    generate_schemas=True,  # Create Table if it not exist
    add_exception_handlers=True,
)
