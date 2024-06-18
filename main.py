from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QFormLayout, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QListWidget, QMessageBox, QCheckBox, QHBoxLayout, QGroupBox, QFileDialog, QListWidgetItem, QInputDialog
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QIcon
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import json
import sys

# Generar una clave a partir de una contraseña
def generar_clave(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encriptar datos
def encriptar(mensaje, clave):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(mensaje.encode()) + encryptor.finalize()
    return urlsafe_b64encode(iv + ct).decode()

# Desencriptar datos
def desencriptar(token, clave):
    token = urlsafe_b64decode(token)
    iv = token[:16]
    ct = token[16:]
    cipher = Cipher(algorithms.AES(clave), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

# Guardar datos en un archivo encriptado
def guardar_datos(nombre_archivo, datos_encriptados, salt):
    try:
        with open(nombre_archivo, 'w') as archivo:
            archivo.write(datos_encriptados)
        with open(nombre_archivo + '.salt', 'wb') as archivo:
            archivo.write(salt)
    except Exception as e:
        print(f"Error al guardar datos: {e}")

# Leer datos de un archivo encriptado
def leer_datos(nombre_archivo):
    try:
        with open(nombre_archivo, 'r') as archivo:
            datos_encriptados = archivo.read()
        with open(nombre_archivo + '.salt', 'rb') as archivo:
            salt = archivo.read()
        return datos_encriptados, salt
    except Exception as e:
        print(f"Error al leer datos: {e}")
        return None, None

# Clase principal de la aplicación
class PasswordManagerApp(QMainWindow):
    def __init__(self):
        super(PasswordManagerApp, self).__init__()

        self.setWindowTitle('Password Manager')
        self.setGeometry(100, 100, 600, 700)
        self.setStyleSheet("""
            QWidget {
                font-family: 'Open Sans', sans-serif;
                font-size: 14px;
            }
            QLabel {
                font-size: 16px;
                font-weight: bold;
            }
            QLineEdit, QTextEdit {
                font-size: 14px;
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 5px;
                margin-bottom: 10px;
            }
            QPushButton {
                font-size: 14px;
                padding: 10px;
                background-color: #007BFF;
                color: white;
                border: none;
                border-radius: 5px;
                margin: 5px 0;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QListWidget {
                font-size: 14px;
                padding: 10px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
        """)

        self.layout = QVBoxLayout()

        self.logo_label = QLabel()
        self.layout.addWidget(self.logo_label, alignment=Qt.AlignCenter)  # Posiciona el logo en el centro superior

        self.platform_title = QLabel()
        self.layout.addWidget(self.platform_title, alignment=Qt.AlignCenter)

        self.form_layout = QFormLayout()
        self.platform_input = QLineEdit()
        self.form_layout.addRow('Platform:', self.platform_input)
        
        self.email_input = QLineEdit()
        self.form_layout.addRow('Email:', self.email_input)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.form_layout.addRow('Password:', self.password_input)
        
        self.show_password_checkbox = QCheckBox('Show Password')
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        self.form_layout.addRow(self.show_password_checkbox)
        
        self.backup_codes_input = QTextEdit()
        self.form_layout.addRow('Backup Codes:', self.backup_codes_input)
        
        self.master_password_input = QLineEdit()
        self.master_password_input.setEchoMode(QLineEdit.Password)
        self.form_layout.addRow('Master Password:', self.master_password_input)
        
        self.logo_input = QPushButton('Choose Logo')
        self.logo_input.clicked.connect(self.choose_logo)
        self.form_layout.addRow('Logo:', self.logo_input)
        
        form_group = QGroupBox("Platform Details")
        form_group.setLayout(self.form_layout)
        self.layout.addWidget(form_group)

        self.buttons_layout = QHBoxLayout()
        self.add_platform_button = QPushButton('Add Platform')
        self.add_platform_button.clicked.connect(self.add_or_update_platform)
        self.buttons_layout.addWidget(self.add_platform_button)

        self.new_platform_button = QPushButton('New Platform')
        self.new_platform_button.clicked.connect(self.clear_inputs)
        self.new_platform_button.setVisible(False)
        self.buttons_layout.addWidget(self.new_platform_button)

        buttons_group = QGroupBox("Actions")
        buttons_group.setLayout(self.buttons_layout)
        self.layout.addWidget(buttons_group)

        self.save_button = QPushButton('Save Data')
        self.save_button.clicked.connect(self.save_data)
        self.layout.addWidget(self.save_button)

        self.load_button = QPushButton('Load Data')
        self.load_button.clicked.connect(self.load_data)
        self.layout.addWidget(self.load_button)

        self.platforms_list = QListWidget()
        self.platforms_list.itemClicked.connect(self.display_platform_data)
        self.layout.addWidget(self.platforms_list)

        self.container = QWidget()
        self.container.setLayout(self.layout)
        self.setCentralWidget(self.container)

        self.data = {}
        self.salt = None
        self.current_platform = None
        self.load_initial_data()

    def load_initial_data(self):
        data_encrypted, salt = leer_datos("backup_contrasenas.txt")
        if data_encrypted is not None and salt is not None:
            self.salt = salt
            password, ok = QInputDialog.getText(self, 'Input Dialog', 'Enter master password:', QLineEdit.Password)
            if ok and password:
                key = generar_clave(password, self.salt)
                try:
                    data_decrypted = desencriptar(data_encrypted, key)
                    self.data = json.loads(data_decrypted)
                    self.update_platforms_list()
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to load data: Incorrect master password.")
            else:
                QMessageBox.warning(self, "Error", "Master password is required to load data.")
                sys.exit()  # Close the application if the password is not provided or the dialog is canceled
        else:
            self.salt = os.urandom(16)

    def toggle_password_visibility(self):
        if self.show_password_checkbox.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)

    def choose_logo(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Choose Logo", "", "Image Files (*.png *.jpg *.bmp)", options=options)
        if fileName:
            self.logo_path = fileName
            pixmap = QPixmap(fileName)
            self.logo_label.setPixmap(pixmap.scaled(100, 100, Qt.KeepAspectRatio))
            self.logo_input.setText('Update Logo')

    def add_or_update_platform(self):
        try:
            platform = self.platform_input.text()
            email = self.email_input.text()
            password = self.password_input.text()
            backup_codes = self.backup_codes_input.toPlainText().split(',')
            master_password = self.master_password_input.text()
            if not master_password:
                QMessageBox.warning(self, "Input Error", "Master password is required.")
                return
            if platform and email and password:
                if self.current_platform:  # Update existing platform
                    self.data[self.current_platform] = {
                        "correo": email,
                        "contrasena": password,
                        "codigos_respaldo": backup_codes,
                        "logo": self.logo_path if self.logo_path else self.data[self.current_platform].get("logo")
                    }
                    QMessageBox.information(self, "Success", f"Updated platform {self.current_platform}")
                else:  # Add new platform
                    self.data[platform] = {
                        "correo": email,
                        "contrasena": password,
                        "codigos_respaldo": backup_codes,
                        "logo": self.logo_path
                    }
                    self.current_platform = platform
                    QMessageBox.information(self, "Success", f"Added platform {platform}")
                self.update_platforms_list()
                self.display_platform_data(QListWidgetItem(platform))
                self.new_platform_button.setVisible(True)
            else:
                QMessageBox.warning(self, "Input Error", "Please provide all the information")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add or update platform: {e}")

    def save_data(self):
        try:
            password = self.master_password_input.text()
            if not password:
                QMessageBox.warning(self, "Input Error", "Master password is required to save data.")
                return
            key = generar_clave(password, self.salt)
            data_encrypted = encriptar(json.dumps(self.data), key)
            guardar_datos("backup_contrasenas.txt", data_encrypted, self.salt)
            QMessageBox.information(self, "Success", "Data saved successfully")
            self.clear_inputs()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save data: {e}")

    def load_data(self):
        try:
            password = self.master_password_input.text()
            if not password:
                QMessageBox.warning(self, "Input Error", "Master password is required to load data.")
                return
            data_encrypted, salt = leer_datos("backup_contrasenas.txt")
            if data_encrypted is not None and salt is not None:
                key = generar_clave(password, salt)
                try:
                    data_decrypted = desencriptar(data_encrypted, key)
                    self.data = json.loads(data_decrypted)
                    self.update_platforms_list()
                    QMessageBox.information(self, "Success", "Data loaded successfully")
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to load data: Incorrect master password.")
            else:
                QMessageBox.warning(self, "Error", "No data to load or error reading data files.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load data: {e}")

    def update_platforms_list(self):
        self.platforms_list.clear()
        for platform in self.data.keys():
            item = QListWidgetItem(platform)
            if "logo" in self.data[platform] and self.data[platform]["logo"]:
                item.setIcon(QIcon(self.data[platform]["logo"]))
            self.platforms_list.addItem(item)

    def display_platform_data(self, item):
        platform = item.text()
        self.current_platform = platform
        self.platform_title.setText(platform)
        self.platform_input.setText(platform)
        self.platform_input.setDisabled(True)
        self.email_input.setText(self.data[platform]["correo"])
        self.password_input.setText(self.data[platform]["contrasena"])
        if "codigos_respaldo" in self.data[platform]:
            self.backup_codes_input.setText(", ".join(self.data[platform]["codigos_respaldo"]))
        else:
            self.backup_codes_input.clear()
        if "logo" in self.data[platform] and self.data[platform]["logo"]:
            pixmap = QPixmap(self.data[platform]["logo"])
            self.logo_label.setPixmap(pixmap.scaled(100, 100, Qt.KeepAspectRatio))
            self.logo_input.setText('Update Logo')
        else:
            self.logo_label.clear()
            self.logo_input.setText('Choose Logo')
        self.add_platform_button.setText('Update Platform')
        self.new_platform_button.setVisible(True)

    def clear_inputs(self):
        self.platform_input.clear()
        self.platform_input.setDisabled(False)
        self.email_input.clear()
        self.password_input.clear()
        self.backup_codes_input.clear()
        self.master_password_input.clear()
        self.logo_label.clear()
        self.platform_title.clear()
        self.logo_path = None
        self.logo_input.setText('Choose Logo')
        self.add_platform_button.setText('Add Platform')
        self.new_platform_button.setVisible(False)

# Ejecución de la aplicación
if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = PasswordManagerApp()
    main_window.show()
    sys.exit(app.exec_())