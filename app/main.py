from ui.main_window import MainWindow
from PyQt6.QtWidgets import QApplication
import sys

if __name__ == "__main__": 
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(1024, 600)
    window.show()
    sys.exit(app.exec())