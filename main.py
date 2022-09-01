
# FastAPI import
from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise
from webapps.authentication.auth import router as webauth


app = FastAPI()

app.include_router(webauth)

register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': [
        'webapps.authentication.models'
    ]},
    generate_schemas=True,  # Create Table if it not exist
    add_exception_handlers=True,
)
