# 🔐 Password Hint Manager

A secure, local, and desktop-based application to store and manage your password hints. Built with Python, Tkinter, and strong encryption.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
![Made with Tkinter](https://img.shields.io/badge/Made%20with-Tkinter-orange)

## ✨ About The Project

Password Hint Manager is a simple yet powerful desktop application designed to help you securely store hints for your various online accounts. Instead of storing plaintext passwords, which is a significant security risk, this application allows you to save memorable hints. All your data is encrypted with a master password and stored locally on your machine, ensuring you have full control over your information.

The application features a modern and intuitive user interface built with Tkinter, providing all the essential functionalities like adding, viewing, updating, and deleting hints in a clean and organized manner.


### Key Features

*   **🔒 Secure Encryption**: Your hints are encrypted using the `cryptography` library (Fernet, AES-128 in CBC mode). The encryption key is derived from your master password using PBKDF2.
*   **🔑 Master Password Protection**: The entire database is locked behind a single, strong master password.
*   **💻 Local Storage**: All data is stored in a local SQLite database (`password_hints.db`), meaning your information never leaves your computer.
*   **✨ Modern UI**: A clean, responsive, and user-friendly interface built with Python's standard GUI library, Tkinter, and styled with TTK themes.
*   **➕ CRUD Functionality**: Easily **C**reate, **R**ead, **U**pdate, and **D**elete your password hints.
*   **🔍 Search & Filter**: Instantly find the hint you're looking for by searching for the service, username, or category.
*   **📤 Data Export**: Backup your hints by exporting them to a human-readable JSON file.
*   **🔄 Secure Reset**: An option to completely reset the application and delete all stored data if you forget your master password.

## 🛠️ Built With

This project is built using the following technologies:

*   [Python 3](https://www.python.org/)
*   [Tkinter](https://docs.python.org/3/library/tkinter.html) (for the GUI)
*   [SQLite3](https://docs.python.org/3/library/sqlite3.html) (for the local database)
*   [Cryptography](https://cryptography.io/en/latest/) (for encryption and key derivation)

## 🚀 Getting Started

Follow these steps to get a local copy up and running.

### Prerequisites

Make sure you have Python 3 and pip installed on your system.

*   **Python 3.6+**
*   **pip** (Python package installer)

### Installation

1.  **Clone the repository**
    ```sh
    git clone https://github.com/azario0/PasswordHintManager.git
    cd PasswordHintManager
    ```

2.  **Install the required package**
    The only external dependency is the `cryptography` library.
    ```sh
    pip install cryptography
    ```

3.  **Run the application**
    ```sh
    python password_hint_manager.py
    ```

## 📖 Usage

1.  **First-Time Setup**: On the first launch, the application will prompt you to create a new Master Password. This password will be used to encrypt and decrypt all your data. **Choose a strong, memorable password, as there is no recovery option.**

2.  **Login**: On subsequent launches, enter your Master Password to unlock the application and access your hints.

3.  **Adding a Hint**:
    *   Fill in the "Service/Website," "Username/Email," "Category," and "Password Hint" fields in the left panel.
    *   Click the **"Add Hint"** button.

4.  **Viewing a Hint**:
    *   Select a hint from the list on the right.
    *   Click the **"View Hint"** button to see the decrypted hint in a popup window.

5.  **Updating a Hint**:
    *   Double-click a hint in the list to load its details into the form on the left.
    *   Make your changes and click the **"Update"** button.

6.  **Deleting a Hint**:
    *   Select a hint from the list.
    *   Click the **"Delete"** button and confirm the action.

7.  **Exporting Data**:
    *   Click the **"Export"** button to save all your decrypted hints to a timestamped JSON file in the application's root directory. This is useful for backups.

8.  **Resetting Password**:
    *   If you forget your master password, you can click the **"Reset Password"** button on the login screen.
    *   **⚠️ WARNING:** This action is irreversible and will permanently delete all your stored hints to ensure security.

## 🛡️ Security Considerations

*   **Key Derivation**: The encryption key is derived from your master password using **PBKDF2 with SHA-256**, which helps protect against brute-force attacks.
*   **Data Encryption**: The hints themselves are encrypted using **Fernet symmetric encryption** (AES-128).
*   **Local-Only**: Your data is never sent over the internet and remains entirely on your local machine.
*   **Master Password Strength**: The overall security of your stored hints depends heavily on the strength and secrecy of your master password.

This application is intended for storing *hints*, not the actual passwords themselves.

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.