from sqlalchemy import create_engine, Column, Integer, String, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import enum

DATABASE_URL = "mysql+pymysql://admin:admin@localhost:3306/crypto"

engine = create_engine(DATABASE_URL, echo=False)
Session = sessionmaker(bind=engine)
Base = declarative_base()

class AlgorithmType(enum.Enum):
    simetric = "simetric"
    asimetric = "asimetric"
    
class Algorithms(Base):
    __tablename__ = "Algorithms"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    type = Column(Enum(AlgorithmType), nullable=False)

class Frameworks(Base):
    __tablename__ = "Frameworks"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    
def init_db():
    Base.metadata.create_all(engine)