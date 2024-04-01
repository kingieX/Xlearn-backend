from fastapi import Depends, FastAPI, HTTPException,Request,status,Query,Body
from fastapi.responses import JSONResponse,Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError,SQLAlchemyError
from sqlalchemy import text
from datetime import datetime
import crud,schemas,models
from typing import Annotated
import database 
from typing import Any
import config
import utils
import jwt
from uuid import uuid4
import logging


models.database.Base.metadata.create_all(bind=database.engine)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

jwtb = utils.JWTBearer()
# In-memory cache for user data
user_cache = {}

app = FastAPI()
origins = [
    "http://127.0.0.1:8000/",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Add your React app's URL here
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/info")
async def info() -> dict[str, str]:
    return {
        "app_name": config.settings.app_name,
        "admin_email": config.settings.admin_email,
    }

@app.post("/signup")
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)) -> JSONResponse:
     hashed_password = utils.get_hashed_password(user.password)
     existing_user = db.query(models.User).filter_by(email=user.email).first()
     existing_username = db.query(models.User).filter_by(username=user.username).first()
     if existing_user:
        error_message = {"error": "Email already exists"}
        return JSONResponse(content=error_message, status_code=status.HTTP_404_NOT_FOUND)
     if existing_username:
         error_message = {"error":"Username already exist"}
         return JSONResponse(content=error_message, status_code=status.HTTP_404_NOT_FOUND)
     try:
         new_user = models.User(username=user.username,fullname=user.fullname, email=user.email, password=hashed_password)
         db.add(new_user)
         db.commit()
         db.refresh(new_user)
         # Convert datetime objects to strings
         created_at_str = new_user.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ")
         updated_at_str = new_user.updatedAt.strftime("%Y-%m-%dT%H:%M:%SZ")

         user_dict = {
             "id": new_user.id,
             "username": new_user.username,
             "email": new_user.email,
             "is_active": new_user.is_active,
             "createdAt": created_at_str,
             "updatedAt": updated_at_str,
            }
     
         return JSONResponse(content=user_dict, status_code=status.HTTP_201_CREATED)
     except IntegrityError as e:
         logger.error(f"IntegrityError: {e}")
         db.rollback()
         error_message = {"error": "Username already exists"}
         return JSONResponse(content=error_message, status_code=status.HTTP_400_BAD_REQUEST)



@app.post("/login", summary="Create access and refresh tokens for user", response_model=schemas.Token)
async def login(request: schemas.UserIn, db: Session = Depends(get_db)) -> dict[str, str]:
    # Log the login attempt
    logger.info(f"Login attempt from email: {request.email}")

    try:
        user = crud.get_user_by_email(db=db, email=request.email)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email",
            )

        hashed_pass = user.password
        if not utils.verify_password(request.password, hashed_pass):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
            )

        # Generate access and refresh tokens
        access = utils.create_access_token(subject=user.id)
        refresh = utils.create_refresh_token(user.id)

        # Create and save token data
        token_db = models.Token(user_id=user.id, access_token=access, refresh_token=refresh, status=True)
        db.add(token_db)
        db.commit()
        db.refresh(token_db)

        # Log successful login
        logger.info(f"Login successful for user: {user.email}")

        return {"user_id": user.id, "access_token": access, "refresh_token": refresh}
    except Exception as e:  # Broad exception handling
        # Log the error
        logger.error(f"Login failed for email: {request.email}: {e}")
        raise e  # Re-raise the exception

@app.post('/change-password')
def change_password(request: schemas.changepassword, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")

    if not utils.validate_password(request.new_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password does not meet minimum requirements")

    if not utils.verify_password(request.old_password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old password")

    try:
        user.password = utils.get_hashed_password(request.new_password)
        db.commit()
        # Log successful password change
        logger.info(f"User: {user.email} successfully changed their password")
        return {"message": "Password changed successfully"}
    except Exception as e:
        # Log the error
        logger.error(f"Error changing password for user: {user.email}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error changing password")


@app.post('/logout')
def logout(dependencies=Depends(utils.JWTBearer()), db: Session = Depends(get_db)):
    token=dependencies
    payload = jwt.decode(token, utils.JWT_SECRET_KEY, utils.ALGORITHM)
    user_id = payload['sub']
    token_record = db.query(models.Token).all()
    info=[]
    for record in token_record :
        print("record",record)
        if (datetime.utcnow() - record.created_date).days >1:
            info.append(record.user_id)
    if info:
        existing_token = db.query(models.Token).where(models.Token.user_id.in_(info)).delete()
        db.commit()
        
    existing_token = db.query(models.Token).filter(models.Token.user_id == user_id, models.Token.access_toke==token).first()
    if existing_token:
        existing_token.status=False
        db.add(existing_token)
        db.commit()
        db.refresh(existing_token)
    return {"message":"Logout Successfully"}


@app.get("/users")
async def get_users(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=10, ge=1, le=100),
    sort_by: str = Query(default="id", allowed=["id", "email", "created_at"]),
    sort_order: str = Query(default="asc", allowed=["asc", "desc"]),
    filter_by: str = Query(default=None),
):
    offset = (page - 1) * per_page
    cache_key = f"users_page_{page}_per_page_{per_page}"
    cached_users = user_cache.get(cache_key)

    if not cached_users:
        query = db.query(models.User)

        if filter_by:
            try:
                filter_by_field, filter_value = filter_by.split(":")
                query = query.filter(getattr(models.User, filter_by_field) == filter_value)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid filter format.")
        order_by_clause = text(f"{sort_by} {sort_order}")
        query = query.order_by(order_by_clause)
        users = query.limit(per_page).offset(offset).all()
        user_cache[cache_key] = users

    # Return cached or retrieved users
    return users




@app.get("/users/{user_id}", response_model= schemas.UserOut)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return db_user

@app.post("/course",status_code=201)
def create_course(course: schemas.CourseBase, db: Session = Depends(get_db)):
        new_course = models.Course(**course.dict())
        db.add(new_course)
        db.commit()
        db.refresh(new_course)
        logger.info("New course created successfully.")
        return new_course


@app.get("/courses")
def read_courses(db: Session = Depends(get_db)):
    all_courses = db.query(models.Course).all()
    return all_courses

@app.get("/course/{id}",status_code=200)
def get(id:int,db:Session=Depends(get_db)):
    db_course = db.query(models.Course).filter(models.Course.id == id).first()
    if db_course == None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"course with such {id} does not exist")
    return db_course

@app.delete("/delete/{id}",status_code=204)
def delete_course(id:int,db:Session=Depends(get_db)):
    delete_course = db.query(models.Course).filter(models.Course.id == id).first()
    if delete_course == None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"course with such {id} does not exist")
    else:
        db.query(models.Course).filter_by(id=id).delete()
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.put("/update/course/{id}")
def course_update(id: int, course: schemas.CourseUpdate, db: Session = Depends(get_db)):
    updated_course = db.query(models.Course).filter(models.Course.id == id).first()

    if updated_course is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Course with ID {id} not found")

    # Update the attributes of the existing course
    for key, value in course.dict().items():
        setattr(updated_course, key, value)

    db.commit()
    db.refresh(updated_course)

    return updated_course

@app.post("/recommend")
async def recommend_course(request: Request) -> dict[str, str] | dict[str, list[Any]]:
    # Get the course name from the request body
    data = await request.json()
    course_name = data.get("course_name")

    # Check if the course is found
    if course_name not in crud.courses_list['course_name'].values:
        return {"message": "Course not found"}

    # Get recommendations
    recommended_courses = crud.recommend(course_name)

    # Return the response
    return {"recommended_courses": recommended_courses}

