from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
from db.db_manager import Session, Algorithms, Frameworks, Files, CryptoKeys
import os
import base64
import subprocess
from utils.style_loader import load_style
from sqlalchemy import case
from utils.enums import FileStatus

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

        # Restul interfeței
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
            
        session = Session()
        
        key_bytes = os.urandom(32)
        encoded_key = base64.b64encode(key_bytes).decode()
        
        new_key = CryptoKeys(
            value = encoded_key,
            algorithm_id = algorithm_id
        )
        
        session.add(new_key)
        session.commit()
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
        if key_id is None:
            QMessageBox.warning(self, "Eroare", "Selecteaza o cheie pentru criptare.")
            return

        session = Session()
        file = session.query(Files).filter(Files.id == file_id).first()
        key = session.query(CryptoKeys).filter(CryptoKeys.id == key_id).first()
        session.close()
        
        if not file or not key:
            QMessageBox.critical(self, "Eroare", "Fisierul sau cheia nu au putut fi incarcate.")
            return
        
        if file.status != FileStatus.original:
            QMessageBox.warning(self, "Atentie", "Doar fisiere cu status 'original' pot fi criptate.")
            return

        input_path = file.file_path
        
        output_dir = "/home/david/Proiecte/crypto-manager/encrypted_files"
        os.makedirs(output_dir, exist_ok=True)
        
        filename = os.path.basename(input_path)
        output_path = os.path.join(output_dir, filename + ".enc")

        # Decodificare cheie
        try:
            key_bytes = base64.b64decode(key.value)
            key_hex = key_bytes.hex()
        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Cheia nu poate fi decodificata:\n{e}")
            return

        iv_hex = "00000000000000000000000000000000"

        try:
            # comanda openssl
            result = subprocess.run([
                "openssl", "enc", "-aes-256-cbc", "-salt",
                "-in", input_path,
                "-out", output_path,
                "-K", key_hex,
                "-iv", iv_hex
            ])

            if result.returncode != 0:
                raise Exception(result.stderr)

            session = Session()
            encrypted_file = Files(
                original_name=os.path.basename(output_path),
                file_path=output_path,
                status="encrypted"
            )
            session.add(encrypted_file)
            session.commit()
            session.close()

            QMessageBox.information(self, "Succes", f"Fisierul a fost criptat:\n{output_path}")
            self.load_files()

        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Criptarea a esuat:\n{e}")
            
    def decrypt_file(self):
        selected_item = self.files_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Eroare", "Selecteaza un fisier din lista.")
            return

        file_id = selected_item.data(Qt.ItemDataRole.UserRole)
        key_id = self.key_combo.currentData()

        if key_id is None:
            QMessageBox.warning(self, "Eroare", "Selecteaza o cheie pentru decriptare.")
            return

        session = Session()
        file = session.query(Files).filter(Files.id == file_id).first()
        key = session.query(CryptoKeys).filter(CryptoKeys.id == key_id).first()
        session.close()

        if not file or not key:
            QMessageBox.critical(self, "Eroare", "Fisierul sau cheia nu au putut fi incarcate.")
            return

        input_path = file.file_path
        if not input_path.endswith(".enc"):
            QMessageBox.warning(self, "Eroare", "Fisierul selectat nu este criptat (.enc).")
            return

        filename = os.path.basename(input_path).replace(".enc", "")
        output_dir = "/home/david/Proiecte/crypto-manager/decrypted_files"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)

        # Decodificare cheie
        try:
            key_bytes = base64.b64decode(key.value)
            key_hex = key_bytes.hex()
        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Cheia nu poate fi decodificata:\n{e}")
            return

        iv_hex = "00000000000000000000000000000000"

        try:
            result = subprocess.run([
                "openssl", "enc", "-aes-256-cbc", "-d",
                "-in", input_path,
                "-out", output_path,
                "-K", key_hex,
                "-iv", iv_hex
            ], capture_output=True, text=True)

            if result.returncode != 0:
                # raise Exception(result.stderr.strip())
                raise Exception("Eroare")

            # Salvare in DB
            session = Session()
            decrypted_file = Files(
                original_name=os.path.basename(output_path),
                file_path=output_path,
                status="decrypted"
            )
            session.add(decrypted_file)
            session.commit()
            session.close()

            QMessageBox.information(self, "Succes", f"Fisierul a fost decriptat:\n{output_path}")
            self.load_files()

        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Decriptarea a esuat:\n{e}")

