from PyQt6.QtWidgets import *
from db.db_manager import Session, Algorithms, Frameworks

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sistem de criptare fisiere")
        
        self.setup_ui()
        self.populate_comboboxes()
        
    def setup_ui(self):
        # Stare
        self.file_path = ""

        # Layout principal
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()

        # Selectare fișier
        self.file_label = QLabel("Fișier selectat: (niciunul)")
        select_button = QPushButton("Selectează fișier")
        select_button.clicked.connect(self.select_file)

        # Alegere algoritm
        self.algorithm_combo = QComboBox()

        # Alegere framework
        self.framework_combo = QComboBox()

        # Tip operațiune
        self.encrypt_radio = QRadioButton("Criptare")
        self.decrypt_radio = QRadioButton("Decriptare")
        self.encrypt_radio.setChecked(True)
        op_group = QButtonGroup()
        op_group.addButton(self.encrypt_radio)
        op_group.addButton(self.decrypt_radio)

        # Buton execută
        execute_button = QPushButton("Execută")
        execute_button.clicked.connect(self.execute_operation)

        # Eticheta de rezultat
        self.result_label = QLabel("Rezultat: -")

        # Adăugare în layout
        layout.addWidget(self.file_label)
        layout.addWidget(select_button)

        layout.addWidget(QLabel("Alege algoritm:"))
        layout.addWidget(self.algorithm_combo)

        layout.addWidget(QLabel("Alege framework:"))
        layout.addWidget(self.framework_combo)

        op_layout = QHBoxLayout()
        op_layout.addWidget(self.encrypt_radio)
        op_layout.addWidget(self.decrypt_radio)
        layout.addLayout(op_layout)

        layout.addWidget(execute_button)
        layout.addWidget(self.result_label)

        central_widget.setLayout(layout)
        
    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Selectează fișier")
        if file_path:
            self.file_path = file_path
            self.file_label.setText(f"Fișier selectat: {file_path}")

    def execute_operation(self):
        if not self.file_path:
            QMessageBox.warning(self, "Eroare", "Selectează un fișier mai întâi.")
            return
        
    def populate_comboboxes(self):
        session = Session()
        
        # Populate algoritmi
        self.algorithm_combo.clear()
        for alg in session.query(Algorithms).all():
            self.algorithm_combo.addItem(alg.name, userData=alg.id)

        # Populate framework-uri
        self.framework_combo.clear()
        for fw in session.query(Frameworks).all():
            self.framework_combo.addItem(fw.name, userData=fw.id)

        session.close()
