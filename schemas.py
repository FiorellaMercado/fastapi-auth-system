from pydantic import BaseModel, EmailStr, field_validator, Field
import re
from datetime import datetime

PATRON_NOMBRE = re.compile(r"[A-Za-zÁÉÍÓÚÜÑáéíóúüñ' -]+")

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    nombre: str = Field(min_length=2, max_length=70)
    apellido: str = Field(min_length=2, max_length=70)
    @field_validator('nombre', 'apellido', mode="before")
    @classmethod
    def validar_texto(cls, value):

        if not isinstance(value, str):
            raise ValueError("Debe ser texto")

        value = value.strip()

        if not PATRON_NOMBRE.fullmatch(value):
            raise ValueError("Solo se permiten letras, espacios, guiones y apóstrofes")
        return value

        return value.strip()



class UserResponse(BaseModel):
    id: int
    email: EmailStr
    rol: str
    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    modo: str

class LoginAttemptResponse(BaseModel):
    email: EmailStr
    ip: str
    is_success: bool
    created_at: datetime
    class Config:
        from_attributes= True

