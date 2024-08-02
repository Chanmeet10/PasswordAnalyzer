import sys
import random
import string
import json
import bcrypt
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (QApplication, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QWidget, QProgressBar, QTextEdit,
                             QMessageBox, QInputDialog)
from cryptography.fernet import Fernet
import os


class PasswordAnalyzer(QWidget):
    def __init__(self):
        super().__init__()

        # Initialize variables
        self.password_history_file = 'password_history.json'
        self.blacklist_file = 'blacklist.txt'
        self.load_password_history()
        self.load_blacklist()
        self.password_last_changed = datetime.now()
        self.expiry_period = timedelta(days=90)

        # Generate or load the encryption key
        self.key = self.load_or_generate_key()
        self.cipher_suite = Fernet(self.key)

        # Initialize UI
        self.initUI()

    def load_or_generate_key(self):
        """Load or generate a new encryption key."""
        key_file = 'secret.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as file:
                return file.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as file:
                file.write(key)
            return key

    def initUI(self):
        """Initialize UI components."""
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter your password here")

        self.result_label = QLabel('Enter a password to see the strength.', self)
        self.suggestions_output = QTextEdit(self)
        self.suggestions_output.setPlaceholderText("Suggestions will appear here...")
        self.suggestions_output.setReadOnly(True)

        # Add text fields for encryption and decryption
        self.encryption_input = QLineEdit(self)
        self.encryption_input.setPlaceholderText("Enter text to encrypt")

        self.encrypted_output = QLineEdit(self)
        self.encrypted_output.setPlaceholderText("Encrypted text will appear here")
        self.encrypted_output.setReadOnly(True)

        self.decryption_input = QLineEdit(self)
        self.decryption_input.setPlaceholderText("Enter text to decrypt")

        self.decrypted_output = QLineEdit(self)
        self.decrypted_output.setPlaceholderText("Decrypted text will appear here")
        self.decrypted_output.setReadOnly(True)

        self.generate_button = QPushButton('Generate Password', self)
        self.generate_button.clicked.connect(self.display_generated_password)

        self.view_history_button = QPushButton('View Password History', self)
        self.view_history_button.clicked.connect(self.view_password_history)

        self.delete_history_button = QPushButton('Delete Password from History', self)
        self.delete_history_button.clicked.connect(self.delete_custom_password)

        self.delete_all_button = QPushButton('Delete All Passwords', self)
        self.delete_all_button.clicked.connect(self.delete_all_passwords)

        self.save_password_button = QPushButton('Save Password', self)
        self.save_password_button.clicked.connect(self.save_password)

        self.encrypt_button = QPushButton('Encrypt Password', self)
        self.encrypt_button.clicked.connect(self.encrypt_password)

        self.decrypt_button = QPushButton('Decrypt Password', self)
        self.decrypt_button.clicked.connect(self.decrypt_password)

        self.set_expiry_button = QPushButton('Set Expiry Period', self)
        self.set_expiry_button.clicked.connect(self.set_expiry_period)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: green; }")

        self.password_input.textChanged.connect(self.analyze_password)

        layout = QVBoxLayout()
        layout.addWidget(self.password_input)
        layout.addWidget(self.result_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.suggestions_output)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.view_history_button)
        layout.addWidget(self.delete_history_button)
        layout.addWidget(self.delete_all_button)
        layout.addWidget(self.save_password_button)
        layout.addWidget(self.encryption_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.encrypted_output)
        layout.addWidget(self.decryption_input)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.decrypted_output)
        layout.addWidget(self.set_expiry_button)

        self.setLayout(layout)
        self.setWindowTitle('Password Strength Analyzer')
        self.show()

    def encrypt_password(self):
        """Encrypt the text using Fernet symmetric encryption."""
        text = self.encryption_input.text()
        if text:
            encrypted_text = self.cipher_suite.encrypt(text.encode()).decode()
            self.encrypted_output.setText(encrypted_text)
        else:
            self.encrypted_output.setText("No text entered to encrypt.")

    def decrypt_password(self):
        """Decrypt the text using Fernet symmetric encryption."""
        encrypted_text = self.decryption_input.text()
        if encrypted_text:
            try:
                decrypted_text = self.cipher_suite.decrypt(encrypted_text.encode()).decode()
                self.decrypted_output.setText(decrypted_text)
            except Exception as e:
                self.decrypted_output.setText(f"Decryption failed: {str(e)}")
        else:
            self.decrypted_output.setText("No encrypted text entered to decrypt.")

    def hash_password(self, password):
        """Hash the given password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def check_password_hash(self, password, hashed_password):
        """Check if the given password matches the hashed password."""
        return bcrypt.checkpw(password.encode(), hashed_password.encode())

    def load_password_history(self):
        """Load password history from a file."""
        try:
            with open(self.password_history_file, 'r') as file:
                self.password_history = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            self.password_history = []

    def save_password_history(self):
        """Save password history to the file."""
        with open(self.password_history_file, 'w') as file:
            json.dump(self.password_history, file)

    def load_blacklist(self):
        """Load a list of commonly used passwords."""
        try:
            with open(self.blacklist_file, 'r') as file:
                self.blacklist = set(line.strip() for line in file)
        except FileNotFoundError:
            self.blacklist = set()

    def check_blacklist(self, password):
        """Check if the password is in the blacklist."""
        if password in self.blacklist:
            return 'Password is too common. Choose a different one.'
        return 'Password is not blacklisted.'

    def analyze_password(self):
        """Analyze the password and provide feedback."""
        password = self.password_input.text()
        if not password:
            self.result_label.setText('Enter a password to see the strength.')
            self.progress_bar.setValue(0)
            self.suggestions_output.setPlainText('')
            return

        # Check if password is blacklisted
        blacklist_result = self.check_blacklist(password)
        if blacklist_result != 'Password is not blacklisted.':
            self.result_label.setText(blacklist_result)
            self.progress_bar.setValue(0)
            self.suggestions_output.setPlainText('')
            return

        # Check if password is in history
        history_result = self.check_password_history(password)
        if history_result != 'Password is not in history.':
            self.result_label.setText(history_result)
            self.progress_bar.setValue(0)
            self.suggestions_output.setPlainText('')
            return

        # Proceed with analysis if not blacklisted or in history
        strength, strength_level, entropy = self.evaluate_password_strength(password)
        breach_result = self.check_password_breach()  # No argument needed
        expiry_result = self.check_password_expiry()
        self.result_label.setText(
            f'Strength: {strength} (Entropy: {entropy:.2f} bits)\n{breach_result}\n{history_result}\n{expiry_result}')
        self.update_progress_bar(strength_level)
        self.suggestions_output.setPlainText(self.generate_suggestions(password))
        self.password_last_changed = datetime.now()  # Update last changed date

    def evaluate_password_strength(self, password):
        """Evaluate the strength of the password."""
        score = 0
        length = len(password)

        # Length check
        if length >= 12:
            score += 2
        elif length >= 8:
            score += 1

        # Character type checks
        if any(char.isdigit() for char in password):
            score += 1
        if any(char.islower() for char in password):
            score += 1
        if any(char.isupper() for char in password):
            score += 1
        if any(char in '!@#$%^&*()-_+=<>?/' for char in password):
            score += 1

        # Determine strength based on score
        strength_levels = {
            0: 'Very Weak',
            1: 'Weak',
            2: 'Moderate',
            3: 'Strong',
            4: 'Very Strong',
            5: 'Excellent',
        }

        # Increase score range for a more accurate assessment
        if score < 2:
            strength = 'Very Weak'
        elif score == 2:
            strength = 'Weak'
        elif score == 3:
            strength = 'Moderate'
        elif score == 4:
            strength = 'Strong'
        elif score == 5:
            strength = 'Very Strong'
        else:
            strength = 'Excellent'

        return strength, strength, self.calculate_entropy(password)

    def calculate_entropy(self, password):
        """Calculate the entropy of the password."""
        char_sets = {
            'lowercase': 26,
            'uppercase': 26,
            'digits': 10,
            'special': 32,
        }
        char_set_size = 0
        if any(char.islower() for char in password):
            char_set_size += char_sets['lowercase']
        if any(char.isupper() for char in password):
            char_set_size += char_sets['uppercase']
        if any(char.isdigit() for char in password):
            char_set_size += char_sets['digits']
        if any(char in '!@#$%^&*()-_+=<>?/' for char in password):
            char_set_size += char_sets['special']

        if char_set_size == 0:
            return 0

        entropy = len(password) * (char_set_size ** 0.5)
        return entropy

    def check_password_breach(self):
        """Simulate checking against a breach database."""
        # For demo purposes, assume no breaches. You can integrate with an actual API.
        return 'Password is not found in known breaches.'

    def check_password_history(self, password):
        """Check if the password is in history."""
        hashed_password = self.hash_password(password)
        for record in self.password_history:
            if isinstance(record, dict) and 'hashed' in record:
                if self.check_password_hash(password, record['hashed']):
                    return 'Password has been used before. Consider using a new one.'
        return 'Password is not in history.'

    def check_password_expiry(self):
        """Check if the password needs to be updated."""
        days_since_last_change = (datetime.now() - self.password_last_changed).days
        if days_since_last_change > self.expiry_period.days:
            return f'Password needs to be updated. Last changed {days_since_last_change} days ago.'
        return f'Password is valid. Last changed {days_since_last_change} days ago.'

    def generate_suggestions(self, password):
        """Generate suggestions to improve the password."""
        suggestions = []
        if len(password) < 12:
            suggestions.append('Consider using a longer password (at least 12 characters).')
        if not any(char.islower() for char in password):
            suggestions.append('Include at least one lowercase letter.')
        if not any(char.isupper() for char in password):
            suggestions.append('Include at least one uppercase letter.')
        if not any(char.isdigit() for char in password):
            suggestions.append('Include at least one digit.')
        if not any(char in '!@#$%^&*()-_+=<>?/' for char in password):
            suggestions.append('Include at least one special character.')
        return '\n'.join(suggestions)

    def update_progress_bar(self, strength_level):
        """Update the progress bar based on strength level."""
        levels = {
            'Very Weak': 0,
            'Weak': 20,
            'Moderate': 40,
            'Strong': 60,
            'Very Strong': 80,
            'Excellent': 100,
        }
        self.progress_bar.setValue(levels.get(strength_level, 0))

    def display_generated_password(self):
        """Generate and display a random password."""
        length, ok = QInputDialog.getInt(self, 'Password Length', 'Enter length of password:', 12, 6, 32, 1)
        if ok:
            password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
            self.password_input.setText(password)

    def view_password_history(self):
        """Display password history."""
        if self.password_history:
            history_str = '\n'.join(
                [f"Original: {record['original']}, Hashed: {record['hashed']}" for record in self.password_history if
                 isinstance(record, dict)])
            self.suggestions_output.setPlainText(f"Password History:\n{history_str}")
        else:
            self.suggestions_output.setPlainText("No passwords in history.")

    def delete_custom_password(self):
        """Delete a specific password from history."""
        password, ok = QInputDialog.getText(self, 'Delete Password', 'Enter the original password to delete:')
        if ok and password:
            self.password_history = [record for record in self.password_history if
                                     not (record.get('original') == password)]
            self.save_password_history()
            self.suggestions_output.setPlainText(f"Deleted '{password}' from history.")

    def delete_all_passwords(self):
        """Delete all passwords from history."""
        self.password_history = []
        self.save_password_history()
        self.suggestions_output.setPlainText("Deleted all passwords from history.")

    def save_password(self):
        """Save the current password to the history."""
        password = self.password_input.text()
        if password:
            hashed_password = self.hash_password(password)
            # Check if password is already in history
            if not any(
                    record.get('original') == password for record in self.password_history if isinstance(record, dict)):
                self.password_history.append({'original': password, 'hashed': hashed_password})
                self.save_password_history()
                self.suggestions_output.setPlainText(f"Saved '{password}' to history.")
            else:
                self.suggestions_output.setPlainText(f"'{password}' is already in history.")
        else:
            self.suggestions_output.setPlainText("No password entered to save.")

    def set_expiry_period(self):
        """Set the expiry period for the password."""
        days, ok = QInputDialog.getInt(self, 'Set Expiry Period', 'Enter expiry period in days:', 90, 1, 365, 1)
        if ok:
            self.expiry_period = timedelta(days=days)
            self.suggestions_output.setPlainText(f"Expiry period set to {days} days.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PasswordAnalyzer()
    sys.exit(app.exec_())
