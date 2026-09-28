import os
from database import SessionLocal
from models import Rol, User
from security import hash_password



def sembrar_datos_iniciales(db):

    respuesta=db.query(Rol).count()
    if respuesta == 0:
        rol_admin=Rol(descripcion="admin")
        rol_usuario=Rol(descripcion="usuario")
        db.add(rol_admin)
        db.add(rol_usuario)
        db.commit()

    ADMIN_EMAIL=os.getenv('ADMIN_EMAIL')
    ADMIN_PASSWORD=os.getenv('ADMIN_PASSWORD')
    usuario_existente= db.query(User).filter(User.email == ADMIN_EMAIL).first()
    if not usuario_existente:
        rol_admin=db.query(Rol).filter(Rol.descripcion == "admin").first()
        nuevo_admin=User(nombre="Admin", apellido="Sistema",
        email=ADMIN_EMAIL, password=hash_password(ADMIN_PASSWORD), rol_id=rol_admin.id)
        db.add(nuevo_admin)
        db.commit()


