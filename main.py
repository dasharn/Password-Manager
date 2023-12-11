import tkinter as tk
from tkinter import messagebox
import re
from cryptography.fernet import Fernet

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

class PasswordManagerGUI:
    """
    A class used to create a GUI for the PasswordManager.

    Attributes
    ----------
    password_manager : PasswordManager
        the password manager to be used
    root : tk.Tk
        the root window
    """

    def __init__(self, password_manager):
        """
        Initialize PasswordManagerGUI with a PasswordManager and a root window.

        Parameters
        ----------
        password_manager : PasswordManager
            the password manager to be used
        """
        self.password_manager = password_manager
        self.root = self.initialize_root_window()
        self.create_widgets()

    def initialize_root_window(self):
        """
        Initialize the root window.

        Returns
        -------
        tk.Tk
            the root window
        """
        root = tk.Tk()
        root.title("Password Manager")
        root.configure(bg="purple")
        root.resizable(False, False)
        return root

    def add_password(self):
        """
        Add a password.

        Get the service, username, and password from the entry fields, check the security of the password,
        and add the password to the password manager. Show a success message if the password was added,
        a warning message if the password is not secure, or an error message if not all fields were filled in.
        """
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not self.password_manager.check_password_security(password):
            messagebox.showwarning("Warning", "Your password is not secure. It should be at least 8 characters long and contain a mix of uppercase and lowercase letters, numbers, and special characters.")
            return

        if self.password_manager.add_password(service, username, password):
            messagebox.showinfo("Success", "Password added successfully!")
        else:
            messagebox.showwarning("Error", "Please fill in all the fields.")

    def get_password(self):
        """
        Get a password.

        Get the service from the entry field and get the password from the password manager.
        Show the username and the password in a message box if the password was found, or an error message if it was not.
        """
        service = self.service_entry.get()
        username, password = self.password_manager.get_password(service)
        if username and password:
            messagebox.showinfo("Password", f"Username: {username}\nPassword: {password}")
        else:
            messagebox.showwarning("Error", "Password not found.")

    def create_widgets(self):
        """
        Create the widgets for the root window.

        The widgets include a frame, labels, entry fields, and buttons.
        """
        instructions = """To add a password, fill in all fields and click 'Add Password.' 
        To view a password, enter the Account Name and click 'Get Password."""
        signature = "Dash"

        center_frame = self.create_frame(self.root, "#d3d3d3", 0, 0)

        self.create_label(center_frame, instructions, 0, 1)
        self.service_entry = self.create_entry(center_frame, "Account:", 1)
        self.username_entry = self.create_entry(center_frame, "Username:", 2)
        self.password_entry = self.create_entry(center_frame, "Password:", 3, show="*")
        
        self.create_button(center_frame, "Add Password", self.add_password, 5, 4)
        self.create_button(center_frame, "Get Password", self.get_password, 6, 4)

        self.create_label(center_frame, signature, 7, 1)

    def create_frame(self, parent, bg, row, column):
        """
        Create a frame.

        Parameters
        ----------
        parent : tk.Widget
            the parent widget
        bg : str
            the background color
        row : int
            the row of the grid where the frame will be placed
        column : int
            the column of the grid where the frame will be placed

        Returns
        -------
        tk.Frame
            the created frame
        """
        frame = tk.Frame(parent, bg=bg)
        frame.grid(row=row, column=column, padx=10, pady=10)
        return frame

    def create_label(self, parent, text, row, column):
        """
        Create a label.

        Parameters
        ----------
        parent : tk.Widget
            the parent widget
        text : str
            the text of the label
        row : int
            the row of the grid where the label will be placed
        column : int
            the column of the grid where the label will be placed
        """
        label = tk.Label(parent, text=text, bg="#d3d3d3")
        label.grid(row=row, column=column, padx=10, pady=5)

    def create_entry(self, parent, label_text, row, show=None):
        """
        Create an entry field with a label.

        Parameters
        ----------
        parent : tk.Widget
            the parent widget
        label_text : str
            the text of the label
        row : int
            the row of the grid where the entry field will be placed
        show : str, optional
            what to display when typing (default is None, which means that the typed text will be displayed)

        Returns
        -------
        tk.Entry
            the created entry field
        """
        self.create_label(parent, label_text, row, 0)
        entry = tk.Entry(parent, show=show)
        entry.grid(row=row, column=1, padx=10, pady=5)
        return entry

    def create_button(self, parent, text, command, row, column):
        """
        Create a button.

        Parameters
        ----------
        parent : tk.Widget
            the parent widget
        text : str
            the text of the button
        command : function
            the function to be executed when the button is clicked
        row : int
            the row of the grid where the button will be placed
        column : int
            the column of the grid where the button will be placed
        """
        button = tk.Button(parent, text=text, command=command, height=1, width=10)
        button.grid(row=row, column=column, padx=10, pady=5)

    def run(self):
        """
        Run the main loop of tkinter.

        This will display the window and start the event loop.
        """
        self.root.mainloop()
    
if __name__ == "__main__":
    password_manager = PasswordManager()
    gui = PasswordManagerGUI(password_manager)
    gui.run()