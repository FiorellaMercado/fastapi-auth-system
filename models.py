from database import Base
from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey
from datetime import datetime, timezone


class Rol(Base):
    __tablename__="rols"
    id=Column(Integer, primary_key=True, autoincrement=True)
    descripcion=Column(String,unique=True)

class User(Base):
    __tablename__="users"
    id=Column(Integer, primary_key=True, autoincrement=True)
    email=Column(String, unique=True)
    password=Column(String)
    rol_id= Column(Integer, ForeignKey("rols.id"), nullable=False)
    nombre=Column(String)
    apellido=Column(String)


class UserSession(Base):
    __tablename__="sessions"
    id=Column(String, primary_key=True)   # se llena con secrets.token_urlsafe(32)
    #al crear la sesión, no es autoincremental o si no
    # cualquiera puede probar números consecutivos en la cookie y "entrar" como otro usuario 
    # sin necesidad de robar nada, solo adivinando.
    user_id=Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at=Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    expires_at=Column(DateTime(timezone=True), nullable=False)
    csrf_token=Column(String)


class LoginAttempt(Base):
    #Con una foránea estricta un intento con email no registrado no se podría ni guardar (la base rechazaría
    #  el insert), y se pierde el dato de "alguien está 
    # probando emails al azar contra el sistema", información de seguridad muy valiosa.
    __tablename__="login_attempts"
    id=Column(Integer, primary_key=True, autoincrement=True)
    email=Column(String)
    ip=Column(String)
    is_success=Column(Boolean)
    created_at= Column(DateTime(timezone=True), default=datetime.now(timezone.utc), index=True)
