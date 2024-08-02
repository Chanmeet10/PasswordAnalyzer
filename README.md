# PasswordAnalyzer
Introduction
The Password Analyzer project is a security tool designed to assist users in managing and enhancing their passwords. This application evaluates password strength, provides encryption and decryption functionalities, and maintains a history of passwords. It aims to offer a comprehensive solution for creating robust passwords, ensuring they are not easily compromised, and managing their security over time.

Features
Password Strength Analysis: The tool assesses the strength of passwords based on various criteria, including length, character diversity, and entropy. It provides real-time feedback and suggestions to help users create stronger passwords.
Encryption and Decryption: Utilizing symmetric encryption, the Password Analyzer allows users to securely encrypt and decrypt text. This feature ensures sensitive information remains confidential and protected.
Password History Management: The application maintains a history of previously used passwords, allowing users to view, save, and delete entries. This helps avoid reuse of passwords and ensures password history management.
Expiry Management: The tool tracks when passwords were last changed and notifies users if passwords need to be updated, promoting regular updates and enhancing overall security.

Technical Details
Programming Language: Python 3.9
Libraries: PyQt5 (for GUI), bcrypt (for password hashing), cryptography (for encryption/decryption)

Key Components:
Password Analysis Module: Analyzes and rates password strength, offering suggestions for improvement.
Encryption/Decryption Module: Encrypts and decrypts text using the Fernet encryption method.
History Management Module: Manages password history, enabling users to save, view, and delete passwords.

How It Works
Password Analysis: Users enter a password, and the application evaluates its strength based on length, character types, and entropy. The strength rating is displayed on a progress bar with recommendations for improvement.
Encryption/Decryption: Users input text to be encrypted or decrypted. The application uses a symmetric encryption key to transform the text and displays the result in corresponding fields.
History Management: Users can save new passwords, view the history of saved passwords, and delete specific entries or all passwords from the history.
Expiry Management: The application tracks the last change date of the password and alerts users when it is time to update their password.

Testing
The Password Analyzer has undergone rigorous testing to ensure accuracy and functionality. Test cases included evaluating password strength, verifying encryption/decryption processes, and testing password history management. Results showed that the tool performs as expected, providing reliable feedback and managing passwords securely.

User Guide
Password Analysis: Type a password into the input field to receive a strength rating and improvement suggestions.
Encryption/Decryption: Enter text into the respective fields and use the provided buttons to encrypt or decrypt the text.
History Management: Utilize the buttons to generate passwords, view the history, and manage saved passwords.

Conclusion
The Password Analyzer is a comprehensive tool designed to enhance password security through detailed analysis, encryption, and history management. It supports users in creating stronger passwords and maintaining secure practices. Future enhancements could include integrating real-time breach checks and expanding the password suggestion features.
