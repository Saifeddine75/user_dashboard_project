
# Modules Import
from webapps.authentication.utils.regex_tools import RegexChecker

# TODO: Make following class generic instantiate by dict form keys
class RegistrationValidationForm():
    """
    Form Registration Validation class
    """

    def __init__(self, form, *args, **kwargs):
        self.form_errors = None
        self.is_valid = None
        self.validate_form(form)

    def validate_form(self, form):
        self.valid_form = self.validate_fields(form)
        self.is_valid = True if len(self.form_errors) else False

    @classmethod
    def get_valid_form(cls, form):
        return cls(form)

    def errors(self, key=None):
        """ Return errors of form

        Parameters
        ----------
        key : dict key, optional
            Key corresponding to the errors name, by default None

        Returns
        -------
        dict or list
            Return dict with all errors or list of key errors
        """
        if key in self.form_errors:
            return self.form_errors[key]
        else:
            return self.form_errors

    def get(self, key):
        if key in self.valid_form:
            return self.valid_form[key]
        else:
            return None

    def validate_fields(self, form):
        """ Control fields authentification

        Returns
        -------
        dict
            Return form with verified credentials
        """

        self.form_errors = {}

        # TODO: Create generic function to create and append to valid_form following attributes
        username = form.get('username')
        password1 = form.get('password1')
        password2 = form.get('password2')
    
        assert isinstance(username, str), "username not str"
        assert isinstance(password1, str), "password1 not str"
        assert isinstance(password2, str), "password2 not str"

        (valid_username, valid_password) = self.get_valid_credentials(username, password1, password2)

        valid_form = {
            'username': valid_username,
            'password': valid_password,
        }

        return valid_form


    def get_valid_credentials(self, username, password1, password2):
        """ Verify credentials user input 

        Parameters
        ----------
        username : str
            User name form input
        password1 : _type_
            User password form input
        password2 : _type_
            User password confirmation form input

        Returns
        -------
        tuple
            Return tuple of username and password, 
            if verification of input failed, value is set to empty string

        """
        is_email = True if '@' else False

        # Check username
        username = self.get_valid_username(
            username=username,
            password=password1,
            is_email=is_email
        )
        
        # Check password
        password = self.get_valid_password(
            password1=password1,
            password2=password2,
        )

        return (username, password)


    def get_valid_password(self, password1, password2):
        """ Check if password is valid else fill class attribute error dict

        Parameters
        ----------
        password1 : str
            User password form input
        password2 : str
            User password confirmation form input

        Returns
        -------
        str
            Return user password in string type 
        """
        errors = []

        if RegexChecker.check_password(password1):
            errors.append(
                'Password should contains a minimum of 8 character, with lower, upper, number and special character')

        elif password1 != password2:
            errors.append(
                'password and password confirmation must match')

        self.form_errors['password'] = errors

        if not errors:
            return password1
        else:
            return ''


    def get_valid_username(self, password, username, is_email):
        """  Check if username is valid else fill class attribute error dict

        Parameters
        ----------
        password : str
            User password form input
        username : str
            User name form input
        is_email : bool
            This variable is True if username is an email else False

        Returns
        -------
        str
            Return username in string type
        """

        errors = []

        email_id = username.split('@')[0]
        domain_name = username.split('.')[0].split('@')[1]

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

        self.form_errors['username'] = errors

        if not errors:
            return username
        else:
            return ''
