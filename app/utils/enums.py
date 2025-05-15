import enum

class AlgorithmType(enum.Enum):
    simetric = "simetric"
    asimetric = "asimetric"
    
class FileStatus(enum.Enum):
    original = "original"
    encrypted = "encrypted"
    decrypted = "decrypted"