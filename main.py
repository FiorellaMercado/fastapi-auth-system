from fastapi import FastAPI
from database import Base, engine, get_db,SessionLocal
from seed import sembrar_datos_iniciales
import models


app = FastAPI()

Base.metadata.create_all(bind=engine)

try: 
    db=SessionLocal()
    sembrar_datos_iniciales(db)
finally:
    db.close()

