from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    nombre: str
    apellido: str

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

