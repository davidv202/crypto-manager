def load_style(widget, path="/home/david/Proiecte/crypto-manager/app/style/style.qss"):
    try:
        with open(path, "r") as f:
            widget.setStyleSheet(f.read())
    except Exception as e:
        print(f"Nu am putut încărca fișierul style.qss: {e}")