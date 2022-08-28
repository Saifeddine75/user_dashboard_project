# External import
import jwt
from passlib.hash import bcrypt
from sqlalchemy.exc import IntegrityError

# FastAPI import
from fastapi import APIRouter, Request, Form
from fastapi import HTTPException, status

# My FastAPI models
from webapps.authentication.models import Users, Users_Pydantic, UsersIn_Pydantic
from webapps.authentication.utils.form_tools import RegistrationValidationForm
from settings import templates


router = APIRouter(tags=['authentication'])

@router.post('/users', response_model=Users_Pydantic)
async def create_user(user: UsersIn_Pydantic):
    """ Create user with UserIn_Pydantic attributes

    Parameters
    ----------
    user : UsersIn_Pydantic, 
        User instance without read-only attributes

    Returns
    -------
    Users instance, 
        User instance with input credentials, username and hashed password
    """
    user_obj = Users(username=user.username,
                     password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await Users_Pydantic.from_tortoise_orm(user_obj)


@router.get('/register')
async def register(request: Request):

    context = {'request': request}

    return templates.TemplateResponse('authentication/register.html', context)


@router.post('/register', response_model=Users_Pydantic)
async def register(request: Request):
    
    form = await request.form()
    assert len(form.keys()) > 0, "Form is empty"
    print('form', form)
    form = RegistrationValidationForm.get_valid_form(form)

    if not form.is_valid:
        errors = form.form_errors
        print(errors)
        context = {
            'request': request,
            'errors': errors
        }

    else:
        errors = []
        assert isinstance(form.username, str)
        assert isinstance(form.password, str)

        # print('form', form)

        try:
            user = await create_user(
                UsersIn_Pydantic(
                    username=form.get('username'),
                    password_hash=form.get('password')
                )
            )

        except IntegrityError:
            errors.append('Email already registered')

        except Exception as exc:
            # raise HTTPException(
            #     status_code=status.HTTP_401_UNAUTHORIZED,
            #     detail='User not found'
            # )
            print(exc)
            errors.append(str(exc))

        context = {'request': request}

    return templates.TemplateResponse('authentication/register.html', context)
