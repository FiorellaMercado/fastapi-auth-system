from fastapi import FastAPI, Depends, HTTPException, Request,status, Response
from database import Base, engine, get_db,SessionLocal
from sqlalchemy.orm import Session
from seed import sembrar_datos_iniciales
from models import User, Rol, UserSession, LoginAttempt
from schemas import UserCreate, UserResponse, LoginRequest, LoginAttemptResponse
from security import hash_password, verificar_password, descifrar_dato,generar_csrf_token,verificar_jwt, generar_session_id, cifrar_dato, crear_jwt
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone, timedelta
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI()

Base.metadata.create_all(bind=engine)

try: 
    db=SessionLocal()
    sembrar_datos_iniciales(db)
finally:
    db.close()

@app.post("/registro", response_model=UserResponse)
def registro(usuario:UserCreate, db: Session =Depends(get_db)):
    email_normalizado=usuario.email.lower()
    usuario_existente=db.query(User).filter(User.email==email_normalizado).first()
    if not usuario_existente:
        rol_usuario=db.query(Rol).filter(Rol.descripcion=="usuario").first()
        nuevo_usuario=User(nombre=usuario.nombre, apellido=usuario.apellido, 
                           rol_id=rol_usuario.id, email=email_normalizado, 
                           password=hash_password(usuario.password))
        try:
            db.add(nuevo_usuario)
            db.commit()
            db.refresh(nuevo_usuario)

            nuevo_usuario.rol=rol_usuario.descripcion

            return nuevo_usuario
        except IntegrityError as e:
            db.rollback()
            raise HTTPException(status_code=409, detail="error de integridad")
    else:
        raise HTTPException(status_code=409, detail="Este usuario ya esta registrado")

    
@app.post("/login")
def login(usuario: LoginRequest, request:Request, response: Response, db: Session=Depends(get_db)):

    exito=False
    usuario_normalizado=usuario.email.lower()

    intentos_fallidos=db.query(LoginAttempt).filter(LoginAttempt.email==usuario_normalizado,
        LoginAttempt.created_at>(datetime.now(timezone.utc)-timedelta(minutes=15)),
        LoginAttempt.is_success==False).count()

    if intentos_fallidos<5:
        usuario_existente=db.query(User).filter(User.email==usuario_normalizado).first()
        if usuario_existente:
            if verificar_password(usuario.password, usuario_existente.password):
                exito=True
    
    ahora = datetime.now(timezone.utc)

    #guardar el intento exito o fallido a la tabla LoginAttempt
    nuevo_login_attempt=LoginAttempt(email=usuario_normalizado, ip=request.client.host, is_success=exito, 
    created_at=ahora)
    db.add(nuevo_login_attempt)
    db.commit()

    if intentos_fallidos>=5:
        raise HTTPException(status_code=429,detail="Demasiados intentos fallidos. Intenta más tarde")

    if not exito:
        raise HTTPException(status_code=401, detail= "Usuario o contrase;a invalidos")

    # segun modo jwt o cookie

    if usuario.modo == "cookie":
        session_id=generar_session_id()
        csrf_token=generar_csrf_token()
        nuevo_user_session=UserSession(id=session_id, user_id= usuario_existente.id,
                                 created_at=ahora,
                                 expires_at=ahora+timedelta(hours=24),
                                 csrf_token=csrf_token)
        db.add(nuevo_user_session)
        db.commit()
        response.set_cookie(key="session_id", value=session_id,
            httponly=True, secure=True, samesite="Lax", max_age=3600*24)
        return {"csrf_token":csrf_token}
    elif usuario.modo== "jwt":
        payload={
            "sub":str(usuario_existente.id),
            "email": cifrar_dato(usuario_existente.email),
        }
        token=crear_jwt(payload)
        return {"access_token": token, "token_type":"bearer" }
    else:
        raise HTTPException(status_code=422, detail="Modo de autenticacion invalido")


security_scheme = HTTPBearer(auto_error=False)

def get_usuario_actual(request: Request, db: Session = Depends(get_db),
    credenciales: HTTPAuthorizationCredentials = Depends(security_scheme)):
    cookie=request.cookies.get("session_id")
    if cookie:
        user_session=db.query(UserSession).filter(UserSession.id==cookie).first()
        if user_session and (datetime.now(timezone.utc) <  user_session.expires_at):
            usuario=db.query(User).filter(User.id==user_session.user_id).first()
            return usuario
        else:
            raise HTTPException(status_code=401, detail="Cookie invalida")

    else:
        #autorizacion=request.headers.get("Authorization")
        #if autorizacion:
        if credenciales:
            token = credenciales.credentials
            #token=autorizacion.replace('Bearer ','')
            try:
                payload=verificar_jwt(token)
                usuario_jwt=db.query(User).filter(User.email == descifrar_dato(payload['email'])).first()
                if usuario_jwt:
                    return usuario_jwt
                else:
                    raise HTTPException(status_code=401, detail="Token invalido")
            except Exception:
                raise HTTPException(status_code=401, detail="Token invalido")
        else:  
            raise HTTPException(status_code=401, detail="No autenticado. Credenciales no proporcionadas")


@app.get("/prueba")
def prueba(usuario: User = Depends(get_usuario_actual)):
    return {"id": usuario.id, "email": usuario.email}

@app.post("/logout")
def logout(request:Request, response: Response, db: Session=Depends(get_db)):
    cookie=request.cookies.get("session_id")
    if cookie:
        user_session=db.query(UserSession).filter(UserSession.id==cookie).first()
        response.delete_cookie(key="session_id")
        if user_session:
            db.delete(user_session)
            db.commit()
    return {"message":"Logout exitoso"}


def requerir_rol(rol: str):
    def verificar( usuario: User= Depends(get_usuario_actual), db: Session=Depends(get_db)):
        rol_existente=db.query(Rol).filter(Rol.id==usuario.rol_id).first()
        if not rol_existente.descripcion== rol:
            raise HTTPException(status_code=403, detail="Sin permiso para esta acción")
        return usuario
    return verificar


@app.get("/admin/login_attempts", response_model=list[LoginAttemptResponse])
def login_attempts(usuario: User = Depends(requerir_rol("admin")), db: Session= Depends(get_db)):
    db_login_attempts=db.query(LoginAttempt).all()
    return db_login_attempts



