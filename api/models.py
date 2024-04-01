from sqlalchemy import Boolean, Column, ForeignKey, Integer, String,DateTime,Float
from sqlalchemy.orm import relationship
from datetime import datetime
import database


class User(database.Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String,unique=True,index=True)
    fullname = Column(String, nullable=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    createdAt = Column(DateTime, nullable=False, default=datetime.utcnow)
    updatedAt = Column(DateTime, nullable=False, default=datetime.utcnow)


class Token(database.Base):
    __tablename__ = "token"
    user_id = Column(Integer)
    access_token = Column(String(450),primary_key=True)
    refresh_token = Column(String(450),nullable=False)
    status = Column(Boolean)
    created_date = Column(DateTime, default=datetime.utcnow)

class Course(database.Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True)
    course_name = Column(String)
    university = Column(String)
    difficulty_level = Column(String)
    course_rating = Column(String)
    course_URL = Column(String)
    course_description = Column(String)
    skills = Column(String)
    created_at = Column(DateTime, default= datetime.utcnow)


class Rating(database.Base):
    __tablename__ = "ratings"

    rating_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    rating = Column(Integer)
    review = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    course = relationship("Course")


class Enrollment(database.Base):
    __tablename__ = "enrollments"

    enrollment_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False)
    enrollment_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    progress = Column(Integer)

    user = relationship("User")
    course = relationship("Course")


class Feedback(database.Base):
    __tablename__ = "feedbacks"

    feedback_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    subject = Column(String)
    message = Column(String)
    date = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class Recommendation(database.Base):
    __tablename__ = "recommendations"

    recommendation_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recommended_course_id = Column(Integer, ForeignKey("courses.id"), nullable=False)
    recommendation_score = Column(Float)
    date = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    recommended_course = relationship("Course")

class OntologyData(database.Base):
    __tablename__ = "ontology_data"

    ontology_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    learning_goals = Column(String)
    knowledge_level = Column(String)

    user = relationship("User")
