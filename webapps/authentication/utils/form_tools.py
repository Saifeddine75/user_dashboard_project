# Modules Import 
from .regex_tools import RegexChecker
from abc import ABC, abstractmethod

import json


class Form():
    def __init__(self, form, *args, name=None, **kwargs):
        """
        Basic Form class with reutilisable functions

        Parameters
        ----------
        name : str, optional
            Name of the form, by default None
        """
        self.name = name
        self.map_dict(form._dict)


    def map_dict(cls, dict):
        """
        Create attributes from dict representing form fields

        Parameters
        ----------
        dictionnary : _type_
            _description_
        """
        for k, v in dict.items():
            setattr(cls, k, v)
        return super(Form, cls).__init__()


class FormModel(ABC):
    """
    Simple Abstract Base Form model to override

    Parameters
    ----------
    form : Form, optional
        structure containing form fields, by default None
    """
    def __init__(self, form, *args, **kwargs):
        self._form = Form(form)
        self._errors = {}


# TODO: Make following class generic instantiate by dict form keys
class RegistrationValidationForm(FormModel):
    """
    Form Registration Validation class
    """
    def __init__(self, form, *args, **kwargs):
        super(Form).__init__(self, form, *args, **kwargs)
        print("validate_form")
        print('RVF dict', self.__dict__)
        print(self.username)
        self.form.map_dict(form._dict)
        self.is_valid = self.validate_form()
        
    def validate_form(self):
        valid_form = self.validate_fields()
        if valid_form:
            return True
        else:
            return False

    # TODO: User super() to call it from FormModel 
    # to make generic method for other validation forms
    @classmethod
    def get_valid_form(cls, form):
        print("get_valid_form")
        return cls(form)

    @property
    def form_errors(self):
        return self.errors


    def validate_fields(self):
        """ Control fields authentification

        Returns
        -------
        _type_
            _description_
        """
        form = self.form
        print(self.form.username)
        is_email = False

        # TODO: Create generic function to create and append to valid_form following attributes
        print(form.username)
        username = form.username
        password1 = form.password1
        password2 = form.password2
        # password2 = str(form.get('password2'))

        if '@' in username:
            is_email=True

        username, password = self.get_valid_credentials(username, password1[0], password2, is_email=is_email)

        valid_form = {
            'username': username, 
            'password': password,
        }

        return valid_form


    def get_valid_credentials(self, username, password1, password2, is_email):
        # Check username
        username = self.get_valid_username(
            username=username, 
            password=password1, 
            is_email=is_email
        )
        password = self.get_valid_password(
            password1=password1,
            password2=password2, 
        )

        if username and password:
            return username, password
        else:
            return False

    def get_valid_password(self, password1, password2):


        errors = []

        if RegexChecker.check_password(password1):
            errors.append(
                'Password should contains a minimum of 8 character, with lower, upper, number and special character')

        elif password1 != password2:
            errors.append(
                'password and password confirmation should must match')

        self.errors['password'] = errors

        if not errors:
            return password1
        else:
            return False


    def get_valid_username(self, password, username, is_email):
        """ 
        Validate and return username whether it's email or not

        Returns
        -------
        _type_
            _description_
        """

        errors = []

        email_id = username.split('@')[0]
        domain_name = username.split('.')[0].split('@')[1]

        print(password in email_id or password in domain_name)

        if is_email:
            if RegexChecker.check_email(username):
                errors.append(
                    'Email is not valid')
                    
            elif password in email_id or password in domain_name:
                errors.append(
                    'Email should not be similar to your password')   

        else:
            if RegexChecker.check_username(username):
               errors.append(
                    'Username is not valid')

            elif password in username:
                errors.append(
                    'Username should not be similar to your password')

        self.errors['username'] = errors

        if not errors:
            return username
        else:
            return False
