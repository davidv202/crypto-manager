from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms

from app.db.db_manager import Session, Algorithms, Frameworks, Files, CryptoKeys
import os
import base64
import subprocess

from app.utils.benchmark import benchmark_operation
from app.utils.style_loader import load_style
from sqlalchemy import case
from app.utils.enums import FileStatus

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sistem de criptare fisiere")

        self.setup_ui()
        load_style(self)
        self.populate_comboboxes()
        self.load_files()

    def setup_ui(self):
        self.file_path = ""
        self.current_file_id = None

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()

        add_file_button = QPushButton("Adaugă fișier")
        add_file_button.clicked.connect(self.select_file)

        # Fisiere
        self.files_list = QListWidget()
        self.files_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self.algorithm_combo = QComboBox()
        self.key_combo = QComboBox()
        self.framework_combo = QComboBox()

        self.encrypt_radio = QRadioButton("Criptare")
        self.decrypt_radio = QRadioButton("Decriptare")
        self.encrypt_radio.setChecked(True)
        op_group = QButtonGroup()
        op_group.addButton(self.encrypt_radio)
        op_group.addButton(self.decrypt_radio)

        execute_button = QPushButton("Execută")
        execute_button.clicked.connect(self.execute_operation)

        self.generate_key_button = QPushButton("Genereaza cheie")
        self.generate_key_button.clicked.connect(self.generate_key)

        self.delete_file_button = QPushButton("Sterge fisier")
        self.delete_file_button.clicked.connect(self.delete_file)

        layout.addWidget(add_file_button)
        layout.addWidget(QLabel("Fișiere:"))
        layout.addWidget(self.files_list)

        layout.addWidget(QLabel("Alege algoritm:"))
        layout.addWidget(self.algorithm_combo)
        self.algorithm_combo.currentIndexChanged.connect(self.on_algorithm_selected)

        layout.addWidget(QLabel("Alege cheia:"))
        layout.addWidget(self.key_combo)

        layout.addWidget(QLabel("Alege framework:"))
        layout.addWidget(self.framework_combo)

        op_layout = QHBoxLayout()
        op_layout.addWidget(self.encrypt_radio)
        op_layout.addWidget(self.decrypt_radio)
        layout.addLayout(op_layout)

        layout.addWidget(execute_button)
        layout.addWidget(self.generate_key_button)

        layout.addWidget(self.delete_file_button)

        central_widget.setLayout(layout)


    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Selecteaza un fisier")
        if file_path:
            self.file_path = file_path

            session = Session()

            existing_file = session.query(Files).filter(Files.file_path == file_path).first()

            if existing_file:
                QMessageBox.warning(self, "Atentie", f"Fisierul {file_path} exista deja.")
            else:
                new_file = Files(
                    original_name = os.path.basename(file_path),
                    file_path = file_path,
                    status = "original"
                )

                session.add(new_file)
                session.commit()
                session.close()

        self.load_files()

    def delete_file(self):
        selected_item = self.files_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Eroare", "Selecteaza un fisier din lista pentru stergere.")
            return

        file_id = selected_item.data(Qt.ItemDataRole.UserRole)

        reply = QMessageBox.question(
            self,
            "Confirmare stergere",
            "Esti sigur ca vrei sa stergi acest fisier?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        session = Session()
        file = session.query(Files).filter(Files.id == file_id).first()

        if not file:
            QMessageBox.critical(self, "Eroare", "Fisierul nu a fost gasit in baza de date.")
            session.close()
            return

        file_path = file.file_path

        try:
            if os.path.exists(file_path):
                os.remove(file_path)

            session.delete(file)
            session.commit()
            session.close()

            self.load_files()

        except Exception as e:
            session.rollback()
            session.close()
            QMessageBox.critical(self, "Eroare", f"A aparut o eroare la stergere:\n{e}")

    def execute_operation(self):
        selected_item = self.files_list.currentItem()

        if not selected_item:
            QMessageBox.warning(self, "Atentie", "Selecteaza un fisier din lista pentru criptare.")
            return

        if self.encrypt_radio.isChecked():
            self.encrypt_file()
        elif self.decrypt_radio.isChecked():
            self.decrypt_file()
        else:
            QMessageBox.warning(self, "Atentie", "Selecteaza tipul operatiei.")

    def populate_comboboxes(self):
        session = Session()

        self.algorithm_combo.clear()
        for alg in session.query(Algorithms).all():
            self.algorithm_combo.addItem(alg.name, userData=alg.id)

        self.framework_combo.clear()
        for fw in session.query(Frameworks).all():
            self.framework_combo.addItem(fw.name, userData=fw.id)

        session.close()

    def load_files(self):
        self.files_list.clear()

        session = Session()

        status_order = case(
            (Files.status == "original", 0),
            (Files.status == "encrypted", 1),
            (Files.status == "decrypted", 2),
            else_=99
        )

        files = session.query(Files).order_by(status_order, Files.upload_date.desc()).all()

        session.close()

        for file in files:

            status = file.status if isinstance(file.status, str) else file.status.value
            item_text = f"{file.original_name} | {status} | {file.upload_date.strftime('%Y-%m-%d %H:%M:%S')}"

            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, file.id)
            self.files_list.addItem(item)

    def load_keys(self, algorithm_id):
        self.key_combo.clear()
        session = Session()
        keys = session.query(CryptoKeys).filter(CryptoKeys.algorithm_id == algorithm_id).all()
        for key in keys:
            self.key_combo.addItem(f"Cheie #{key.id}", userData=key.id)
        session.close()

    def generate_key(self):
        algorithm_id = self.algorithm_combo.currentData()

        if algorithm_id is None:
            QMessageBox.warning(self, "Atentie", "Selecteaza un algoritm.")
            return

        session = Session()
        algorithm = session.query(Algorithms).filter_by(id=algorithm_id).first()

        if algorithm.name.upper() == "RSA":
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            public_key = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            new_key = CryptoKeys(
                value=public_key,
                algorithm_id=algorithm_id
            )
            session.add(new_key)
            session.commit()

            private_key_path = f"private_keys/private_key_{new_key.id}.pem"
            os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

            with open(private_key_path, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            QMessageBox.information(self, "Informatie", f"Cheie RSA generata:.\nCheia privata: {private_key_path}")
        elif algorithm.name.upper() == "AES":
            key_bytes = os.urandom(32)
            encoded_key = base64.b64encode(key_bytes).decode()

            new_key = CryptoKeys(
                value = encoded_key,
                algorithm_id = algorithm_id
            )

            session.add(new_key)
            session.commit()
        else:
            QMessageBox.warning(self, "Atentie", "Algoritm necunoscut")

        session.close()
        self.load_keys(algorithm_id)


    def on_algorithm_selected(self):
        algorithm_id = self.algorithm_combo.currentData()
        if algorithm_id:
            self.load_keys(algorithm_id)

    def encrypt_file(self):
        selected_item = self.files_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Eroare", "Selecteaza un fisier din lista.")
            return

        file_id = selected_item.data(Qt.ItemDataRole.UserRole)
        key_id = self.key_combo.currentData()
        fw_id = self.framework_combo.currentData()

        if key_id is None or fw_id is None:
            QMessageBox.warning(self, "Eroare", "Selecteaza si cheia, si framework-ul.")
            return

        session = Session()
        file = session.query(Files).filter(Files.id == file_id).first()
        key = session.query(CryptoKeys).filter(CryptoKeys.id == key_id).first()
        algorithm = session.query(Algorithms).filter(Algorithms.id == key.algorithm_id).first()
        framework = session.query(Frameworks).filter(Frameworks.id == fw_id).first()
        session.close()

        if not file or not key or not algorithm or not framework:
            QMessageBox.critical(self, "Eroare", "Datele nu au putut fi incarcate.")
            return

        if file.status != FileStatus.original:
            QMessageBox.warning(self, "Atentie", "Doar fisiere cu status 'original' pot fi criptate.")
            return

        input_path = file.file_path
        filename = os.path.basename(input_path)
        output_dir = "/home/david/Proiecte/crypto-manager/encrypted_files"
        os.makedirs(output_dir, exist_ok=True)

        # AES - OpenSSL
        if algorithm.name.upper() == "AES" and framework.name.lower() == "openssl":
            try:
                key_bytes = base64.b64decode(key.value)
                key_hex = key_bytes.hex()
                iv_hex = "00000000000000000000000000000000"
                output_path = os.path.join(output_dir, filename + ".enc")

                benchmark_operation(
                    lambda: subprocess.run([
                        "openssl", "enc", "-aes-256-cbc", "-salt",
                        "-in", input_path,
                        "-out", output_path,
                        "-K", key_hex,
                        "-iv", iv_hex
                    ], capture_output=True, text=True),
                    file_path=input_path,
                    algorithm_name=algorithm.name,
                    framework_name=framework.name
                )

                session = Session()
                session.add(Files(original_name=filename + ".enc", file_path=output_path, status="encrypted"))
                session.commit()
                session.close()

                QMessageBox.information(self, "Succes", f"Fisierul a fost criptat (AES + OpenSSL):\n{output_path}")
                self.load_files()

            except Exception as e:
                QMessageBox.critical(self, "Eroare", f"Criptarea AES cu OpenSSL a esuat:\n{e}")

        # AES - Cryptography
        elif algorithm.name.upper() == "AES" and framework.name.lower() == "cryptography":
            try:
                key_bytes = base64.b64decode(key.value)
                iv = bytes.fromhex("00000000000000000000000000000000")
                output_path = os.path.join(output_dir, filename + ".enc")

                def aes_crypto_encrypt():
                    with open(input_path, "rb") as f:
                        plaintext = f.read()
                    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
                    encryptor = cipher.encryptor()
                    padding_len = 16 - (len(plaintext) % 16)
                    plaintext += bytes([padding_len] * padding_len)
                    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                    with open(output_path, "wb") as f:
                        f.write(ciphertext)

                benchmark_operation(
                    aes_crypto_encrypt,
                    file_path=input_path,
                    algorithm_name=algorithm.name,
                    framework_name=framework.name
                )

                session = Session()
                session.add(Files(original_name=filename + ".enc", file_path=output_path, status="encrypted"))
                session.commit()
                session.close()

                QMessageBox.information(self, "Succes", f"Fisierul a fost criptat (AES + Cryptography):\n{output_path}")
                self.load_files()

            except Exception as e:
                QMessageBox.critical(self, "Eroare", f"Criptarea AES cu Cryptography a esuat:\n{e}")

        # RSA - OpenSSL
        elif algorithm.name.upper() == "RSA" and framework.name.lower() == "openssl":
            try:
                pub_pem = key.value.encode()
                pub_path = os.path.join(output_dir, f"pubkey_{key.id}.pem")
                with open(pub_path, "wb") as f:
                    f.write(pub_pem)
                output_path = os.path.join(output_dir, filename + ".rsa")

                def rsa_openssl_encrypt():
                    return subprocess.run([
                        "openssl", "rsautl", "-encrypt",
                        "-pubin", "-inkey", pub_path,
                        "-in", input_path,
                        "-out", output_path
                    ], capture_output=True, text=True)

                benchmark_operation(
                    rsa_openssl_encrypt,
                    file_path=input_path,
                    algorithm_name=algorithm.name,
                    framework_name=framework.name
                )

                os.remove(pub_path)

                session = Session()
                session.add(Files(original_name=filename + ".rsa", file_path=output_path, status="encrypted"))
                session.commit()
                session.close()

                QMessageBox.information(self, "Succes", f"Fisierul a fost criptat (RSA + OpenSSL):\n{output_path}")
                self.load_files()

            except Exception as e:
                QMessageBox.critical(self, "Eroare", f"Criptarea RSA cu OpenSSL a esuat:\n{e}")

        # RSA - Cryptography
        elif algorithm.name.upper() == "RSA" and framework.name.lower() == "cryptography":
            try:
                public_key = serialization.load_pem_public_key(key.value.encode())
                with open(input_path, "rb") as f:
                    plaintext = f.read()

                if len(plaintext) > 200:
                    QMessageBox.critical(self, "Eroare", "RSA poate cripta doar fisiere mici (<200 bytes).")
                    return

                output_path = os.path.join(output_dir, filename + ".rsa")

                def rsa_crypto_encrypt():
                    ciphertext = public_key.encrypt(
                        plaintext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    with open(output_path, "wb") as f:
                        f.write(ciphertext)

                benchmark_operation(
                    rsa_crypto_encrypt,
                    file_path=input_path,
                    algorithm_name=algorithm.name,
                    framework_name=framework.name
                )

                session = Session()
                session.add(Files(original_name=filename + ".rsa", file_path=output_path, status="encrypted"))
                session.commit()
                session.close()

                QMessageBox.information(self, "Succes", f"Fisierul a fost criptat (RSA + Cryptography):\n{output_path}")
                self.load_files()

            except Exception as e:
                QMessageBox.critical(self, "Eroare", f"Criptarea RSA cu Cryptography a esuat:\n{e}")

        else:
            QMessageBox.warning(self, "Atentie", f"Combinatie necunoscuta: {algorithm.name} + {framework.name}")

    def decrypt_file(self):
        selected_item = self.files_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Eroare", "Selecteaza un fisier din lista.")
            return

        file_id = selected_item.data(Qt.ItemDataRole.UserRole)
        key_id = self.key_combo.currentData()
        fw_id = self.framework_combo.currentData()

        if key_id is None or fw_id is None:
            QMessageBox.warning(self, "Eroare", "Selecteaza si cheia, si framework-ul.")
            return

        session = Session()
        file = session.query(Files).filter(Files.id == file_id).first()
        key = session.query(CryptoKeys).filter(CryptoKeys.id == key_id).first()
        algorithm = session.query(Algorithms).filter(Algorithms.id == key.algorithm_id).first()
        framework = session.query(Frameworks).filter(Frameworks.id == fw_id).first()
        session.close()

        if not file or not key or not algorithm or not framework:
            QMessageBox.critical(self, "Eroare", "Datele nu au putut fi incarcate.")
            return

        input_path = file.file_path
        filename = os.path.basename(input_path).replace(".enc", "").replace(".rsa", "")
        output_dir = "/home/david/Proiecte/crypto-manager/decrypted_files"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)

        try:
            if algorithm.name.upper() == "AES" and framework.name.lower() == "openssl":
                key_bytes = base64.b64decode(key.value)
                key_hex = key_bytes.hex()
                iv_hex = "00000000000000000000000000000000"

                def aes_openssl_decrypt():
                    subprocess.run([
                        "openssl", "enc", "-aes-256-cbc", "-d",
                        "-in", input_path,
                        "-out", output_path,
                        "-K", key_hex,
                        "-iv", iv_hex
                    ], capture_output=True, text=True, check=True)

                benchmark_operation(
                    aes_openssl_decrypt,
                    file_path=input_path,
                    algorithm_name=algorithm.name,
                    framework_name=framework.name,
                    operation="decrypt"
                )

            elif algorithm.name.upper() == "AES" and framework.name.lower() == "cryptography":
                key_bytes = base64.b64decode(key.value)
                iv = bytes.fromhex("00000000000000000000000000000000")

                def aes_crypto_decrypt():
                    with open(input_path, "rb") as f:
                        ciphertext = f.read()
                    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    padding_len = padded_plaintext[-1]
                    plaintext = padded_plaintext[:-padding_len]
                    with open(output_path, "wb") as f:
                        f.write(plaintext)

                benchmark_operation(
                    aes_crypto_decrypt,
                    file_path=input_path,
                    algorithm_name=algorithm.name,
                    framework_name=framework.name,
                    operation="decrypt"
                )

            elif algorithm.name.upper() == "RSA" and framework.name.lower() == "openssl":
                if not input_path.endswith(".rsa"):
                    QMessageBox.warning(self, "Eroare", "Fisierul selectat nu este criptat cu RSA (.rsa).")
                    return
                private_key_path = os.path.join("private_keys", f"private_key_{key.id}.pem")
                if not os.path.exists(private_key_path):
                    QMessageBox.critical(self, "Eroare", f"Cheia privata nu a fost gasita:\n{private_key_path}")
                    return

                def rsa_openssl_decrypt():
                    subprocess.run([
                        "openssl", "rsautl", "-decrypt",
                        "-inkey", private_key_path,
                        "-in", input_path,
                        "-out", output_path
                    ], capture_output=True, text=True, check=True)

                benchmark_operation(
                    rsa_openssl_decrypt,
                    file_path=input_path,
                    algorithm_name=algorithm.name,
                    framework_name=framework.name,
                    operation="decrypt"
                )

            elif algorithm.name.upper() == "RSA" and framework.name.lower() == "cryptography":
                if not input_path.endswith(".rsa"):
                    QMessageBox.warning(self, "Eroare", "Fisierul selectat nu este criptat cu RSA (.rsa).")
                    return

                private_key_path = os.path.join("private_keys", f"private_key_{key.id}.pem")
                if not os.path.exists(private_key_path):
                    QMessageBox.critical(self, "Eroare", f"Cheia privata nu a fost gasita:\n{private_key_path}")
                    return

                def rsa_crypto_decrypt():
                    with open(private_key_path, "rb") as f:
                        private_key = serialization.load_pem_private_key(f.read(), password=None)
                    with open(input_path, "rb") as f:
                        ciphertext = f.read()
                    plaintext = private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    with open(output_path, "wb") as f:
                        f.write(plaintext)

                benchmark_operation(
                    rsa_crypto_decrypt,
                    file_path=input_path,
                    algorithm_name=algorithm.name,
                    framework_name=framework.name,
                    operation="decrypt"
                )

            else:
                QMessageBox.warning(self, "Atentie", f"Combinatie necunoscuta: {algorithm.name} + {framework.name}")
                return

            session = Session()
            session.add(Files(
                original_name=os.path.basename(output_path),
                file_path=output_path,
                status="decrypted"
            ))
            session.commit()
            session.close()

            QMessageBox.information(self, "Succes", f"Fisierul a fost decriptat:{output_path}")
            self.load_files()

        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Eroare",
                                 f"Comanda a esuat:\n{e.stderr.strip() if hasattr(e, 'stderr') else str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"A aparut o eroare la decriptare:\n{e}")

