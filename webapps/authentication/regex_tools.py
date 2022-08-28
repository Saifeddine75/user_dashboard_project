# External packages import
import re

class RegexChecker():

    @staticmethod
    def check_email(email):
        """
        Verify if email match with email regex

        Parameters
        ----------
        email : str
            Expression to match with regex
        """
        email_regex =\
            '^[a-z0-9]\
            +[\._]\
            ?[a-z0-9]\
            +[@]\w+[.]\w{2,3}$'

        re.search(email_regex, email)


    @staticmethod
    def check_username(username):
        """
        Verify if username match with username regex

        Parameters
        ----------
        username : str
            Expression to match with regex
        """
        username_regex=\
            "^(?=.{4, 32}$)\
            (?![_.-])\
            (?!.*[_.]{2})\
            [a-zA-Z0-9._-]+\
            (?<![_.])$"

        re.search(username_regex, username)


    @staticmethod
    def check_password(password):
        """
        Verify if password match with password regex

        Parameters
        ----------
        password : str
            Expression to match with regex
        """
        password_regex =\
            "^(?=.*[a-z])\
            (?=.*[A-Z])(?=.*\d)\
            (?=.*[ @$!%*?& ])\
            [A-Za-z\d @$!%*?& ]{8, }$"

        re.search(password_regex, password)
