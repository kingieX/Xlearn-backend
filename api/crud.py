from datetime import datetime, timedelta
from typing import Annotated,Any
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from jwt.exceptions import DecodeError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
import models, schemas
import utils 
import config 
from pydantic import EmailStr
import os
import pickle


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login",
                                     scheme_name="JWT")
script_directory = os.path.dirname(os.path.abspath(__file__))
courses_path = os.path.join(script_directory, 'courses.pkl')
similarity_path = os.path.join(script_directory, 'similarity.pkl')
courses_list = pickle.load(open(courses_path, 'rb'))
similarity = pickle.load(open(similarity_path, 'rb'))

def get_user(db: Session, user_id: int) -> schemas.UserOut:
    user = db.query(models.User).filter(models.User.id == user_id).first()

    if user:
        user_out = schemas.UserOut(
            id=user.id,
            username=user.username,
            email=user.email,
            fullname=user.fullname,
            is_active=user.is_active,
        )
        return user_out
    else:
        raise HTTPException(status_code=404, detail="User not found")

def get_user_by_username(db: Session, username: str):
    username_data = db.query(models.User).filter(models.User.username == username).first()
    if username_data:
        user_dict = {
            "id": username_data.id,
            "fullname": username_data.fullname,
            "email": username_data.email,
            "is_active": username_data.is_active,
        }
        return schemas.UserOut(**user_dict)

def get_user_by_email(db: Session, email: EmailStr) -> schemas.User:
    user_data = db.query(models.User).filter(models.User.email == email).first()
    if user_data:
        user = schemas.User(
            id=user_data.id,
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            fullname=user_data.fullname,
            is_active=user_data.is_active,
            createdAt=user_data.createdAt,
            updatedAt=user_data.updatedAt,
        )
        return user
    else:
        raise HTTPException(status_code=404, detail="User not found")


def delete_user(db: Session, user_id: int):
    user = db.query(models.User).filter(models.User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found",
        )

    db.delete(user)
    db.commit()

    return {"status": "success", "message": f"User with id {user_id} deleted"}

     
def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not utils.verify_password(password, user.hashed_password):
        return False
    return user


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def get_current_user(db:Session,token: Annotated[str, Depends(oauth2_scheme)]) -> schemas.UserOut:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.settings.jwt_secret_key, algorithms=[config.settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except DecodeError:
        raise credentials_exception
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(current_user: Annotated[schemas.User, Depends(get_current_user)]):
    if current_user.is_active == 'disabled':
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_courses(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Course).offset(skip).limit(limit).all()


def recommend(course):
    index = courses_list[courses_list['course_name'] == course].index[0]
    distances = sorted(list(enumerate(similarity[index])), reverse=True, key=lambda x: x[1])
    recommended_course_names = []
    for i in distances[1:7]:
        course_name = courses_list.iloc[i[0]].course_name
        recommended_course_names.append(course_name)

    return recommended_course_names
