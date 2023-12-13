import tkinter as tk
from tkinter import messagebox
import re
from cryptography.fernet import Fernet
from gui import Gui
class PasswordManager:
    """
    A class used to manage passwords.

    Attributes
    ----------
    key : bytes
        a key used to encrypt and decrypt passwords
    passwords : dict
        a dictionary that stores service names as keys and username-password pairs as values
    """

    def __init__(self):
        """
        Initialize PasswordManager with a generated key and an empty password dictionary.
        """
        self.key = self.generate_key()
        self.passwords = {}

    def generate_key(self):
        """
        Generate a key for encrypting and decrypting passwords.

        Returns
        -------
        bytes
            the generated key
        """
        return Fernet.generate_key()

    def encrypt_password(self, password):
        """
        Encrypt a password.

        Parameters
        ----------
        password : str
            the password to be encrypted

        Returns
        -------
        str
            the encrypted password
        """
        f = Fernet(self.key)
        return f.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """
        Decrypt a password.

        Parameters
        ----------
        encrypted_password : str
            the password to be decrypted

        Returns
        -------
        str
            the decrypted password
        """
        f = Fernet(self.key)
        return f.decrypt(encrypted_password.encode()).decode()
    
    def check_password_security(self, password):
        """
        Check the security of a password.

        A secure password is at least 8 characters long and contains at least one lowercase letter,
        one uppercase letter, one digit, and one special character.

        Parameters
        ----------
        password : str
            the password to be checked

        Returns
        -------
        bool
            True if the password is secure, False otherwise
        """
        if len(password) < 8:
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[\d]", password):
            return False
        if not re.search(r"[!@#$%^&*()]", password):
            return False
        return True

    def add_password(self, service, username, password):
        """
        Add a password.

        Parameters
        ----------
        service : str
            the name of the service
        username : str
            the username
        password : str
            the password

        Returns
        -------
        bool
            True if the password was added, False otherwise
        """
        if service and username and password:
            encrypted_password = self.encrypt_password(password)
            self.passwords[service] = {'username': username, 'password': encrypted_password}
            return True
        else:
            return False

    def get_password(self, service):
        """
        Get a password.

        Parameters
        ----------
        service : str
            the name of the service

        Returns
        -------
        tuple
            a tuple containing the username and the decrypted password, or (None, None) if the service was not found
        """
        if service in self.passwords:
            encrypted_password = self.passwords[service]['password']
            decrypted_password = self.decrypt_password(encrypted_password)
            return self.passwords[service]['username'], decrypted_password
        else:
            return None, None


    
if __name__ == "__main__":
    password_manager = PasswordManager()
    gui = Gui(password_manager)
    gui.run()