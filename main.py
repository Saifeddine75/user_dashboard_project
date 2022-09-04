
# External import.
import uvicorn

# FastAPI import.
from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise

# App import.
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

if __name__ == "__main__":
    try:
        uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
    except:
        with file(open('log', 'w')):
            
            p = run( [ 'echo', 'hello' ], capture_output=True )

            print( 'exit status:', p.returncode )
            print( 'stdout:', p.stdout.decode() )
            print( 'stderr:', p.stderr.decode() )