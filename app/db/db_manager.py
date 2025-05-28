from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, Enum, ForeignKey, Text, TIMESTAMP, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from app.utils.enums import AlgorithmType, FileStatus

DATABASE_URL = "mysql+pymysql://admin:admin@localhost:3306/crypto"

engine = create_engine(DATABASE_URL, echo=False)
Session = sessionmaker(bind=engine)
Base = declarative_base()
    
class Algorithms(Base):
    __tablename__ = "Algorithms"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    type = Column(Enum(AlgorithmType), nullable=False)

class Frameworks(Base):
    __tablename__ = "Frameworks"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    
class CryptoKeys(Base):
    __tablename__ = "crypto_keys"
    
    id = Column(Integer, primary_key=True)
    value = Column(Text, nullable=False)
    algorithm_id = Column(Integer, ForeignKey("Algorithms.id"), nullable=False)
    key_type = Column(String, nullable=True)
    
    algorithm = relationship("Algorithms")

class Files(Base):
    __tablename__ = "Files"

    id = Column(Integer, primary_key=True)
    original_name = Column(String(255), nullable=False)
    file_path = Column(Text, nullable=False)
    status = Column(Enum(FileStatus), nullable=False, default=FileStatus.original)
    upload_date = Column(TIMESTAMP, server_default=func.now())

class Benchmark(Base):
    __tablename__ = "benchmarks"

    id = Column(Integer, primary_key=True)
    algorithm = Column(String(50))
    framework = Column(String(50))
    operation = Column(String(20))
    time_ms = Column(Float)
    memory_kb = Column(Float)
    file_size_bytes = Column(Integer)
    timestamp = Column(DateTime, default=datetime.now)
    
def init_db():
    Base.metadata.create_all(engine)