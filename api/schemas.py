from pydantic import BaseModel,EmailStr
from datetime import datetime
from typing import List

class Token(BaseModel):
    access_token: str
    refresh_token: str
    user_id: int

class TokenData(BaseModel):
    user_id: str| None = None
    access_token:str
    refresh_token:str
    status: bool
    created_date: datetime


class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    fullname: str | None = None
    is_active: bool | None = None

class User(UserOut):
    password: str
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password:str
    fullname:str | None = None
    is_active: bool | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class UserIn(BaseModel):
    email: EmailStr
    password: str

class UserInDB(User):
    hashed_password: str

class changepassword(BaseModel):
    email: EmailStr
    old_password:str
    new_password:str
    
class CourseBase(BaseModel):
    course_name: str
    university: str
    difficulty_level: str
    course_rating: float
    course_URL: str
    course_description: str
    skills: str

    class Config:
        from_attributes = True  # Enables automatic model creation/update from schema

class CourseOut(BaseModel):
    id: int
    course_name: str
    university: str
    difficulty_level: str
    course_rating:float
    course_URL: str
    course_description: str
    skills: str
    created_at: datetime

    class Config:
        from_attributes = True

class CourseUpdate(BaseModel):
    course_name:str
    university:str
    difficulty_level:str
    course_description:str
    skills: str




    
