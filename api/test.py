import requests
from fastapi import status
import json
import asyncio




BASE_URL = 'http://127.0.0.1:8000/'

def test_recommendation():
    re_url  =  BASE_URL + 'recommend'
    json_data = {
        "course_name": "Business Strategy Business Model Canvas Analysis with Miro"
    }
    
    response = requests.post(re_url, json=json_data)
    
    assert response.status_code == 200  # Assuming 200 is the correct status code for a successful request
    result = response.json()

    # Add assertions based on the expected response format
    assert "recommended_courses" in result
    assert isinstance(result["recommended_courses"], list)

def test_info():
    info_url = BASE_URL + 'info'
    response = requests.get(info_url)
    assert response.status_code == 200
    assert response.json()
    print(response)


def test_signup():
    signup_url = BASE_URL + 'signup'
    user = {
        "username": "test34user",
        "fullname": "Test User",
        "email": f"test34@example.com",
        "password": "Test@password34",
    }

    response = requests.post(signup_url, json=user)
    assert response.json()
    print(response)

def test_login():
    login_url = BASE_URL + "login"

    test_user_data = {
        "email": "test34@example.com",
        "password": "Test@password34",
    }

    response = requests.post(login_url, json=test_user_data)

    # Assert status code
    assert response.status_code == status.HTTP_200_OK, f"Unexpected status code: {response.status_code}"

    # Assert access token presence
    assert "access_token" in response.json(), "Missing access token in response"

    # Assert refresh token presence
    assert "refresh_token" in response.json(), "Missing refresh token in response"

    # Optional: Assert any additional data returned in the response
    # ...

VALID_USER_EMAIL = "test34@example.com"
VALID_USER_PASSWORD = "Test@password34"

def test_change_password():
    change_password_url = BASE_URL + 'change-password'
    old_password = VALID_USER_PASSWORD
    new_password = "Newtestpassword113"
    change_password_data = {
    "email": VALID_USER_EMAIL,
    "old_password": old_password,
    "new_password": new_password,
    }
    change_password_response = requests.post(change_password_url, json=change_password_data)
    print(change_password_response.json)


def test_get_users():

   # Define query parameters
    params = {
        "page": 1,
        "per_page": 10,
        "sort_by": "id",
        "sort_order": "asc",
        "filter_by": None,
    }

    # Make the request with the defined parameters
    response = requests.get("http://127.0.0.1:8000/users", params=params)

    # Check if the request was successful (status code 200)
    assert response.status_code == 200

    # Add more assertions based on your expected response format
    response_json = response.json()
    print(response_json)

def test_read_user():
  
    ruser_url  =  "http://127.0.0.1:8000/users/1" 
    
    # Make the request to the endpoint
    response = requests.get(ruser_url)

    # Check if the request was successful (status code 200)
    assert response.status_code == 200
    if response.status_code == 404:
        assert "User not found" in response.text

def test_create_course_success():
        # Replace with valid course data for testing
        course_data = {
            "course_name": "Test Course",
            "university": "Test University",
            "difficulty_level": "Intermediate",
            "course_rating": 4.5,
            "course_URL": "https://example.com/test-course",
            "course_description": "This is a test course.",
            "skills": "Python, Django",
        }

        response = requests.post(f"{BASE_URL}course", json=course_data)

        # Check if the request was successful (status code 200 or 201 depending on your API)
        assert response.status_code, 201  # Adjust the status code as per your API

        # Add more assertions based on your expected response format
        response_json = response.json()
        print(response_json)

def test_read_course():
  
    course_url  =  "http://127.0.0.1:8000/courses" 
    
    # Make the request to the endpoint
    response = requests.get(course_url)

    # Check if the request was successful (status code 200)
    assert response.status_code == 200
    if response.status_code == 404:
        assert "courses not found" in response.text


def test_get_course():

    id = 1  # Replace with the desired course ID for testing

    # Send GET request to the /course/{id} endpoint
    response = requests.get(f"{BASE_URL}course/{id}")

    # Assert status code
    assert response.status_code == 200

    # Assert response data structure
    data = response.json()
    assert "id" in data
    assert "course_name" in data
    # Add more assertions based on your schema

    print(data)


def test_delete_course():
    # Assuming you have a course with ID 1 to delete
    course_id = 3
    
    # Send DELETE request
    response = requests.delete(f"{BASE_URL}delete/{course_id}")
    # Assert status code
    assert response.status_code == 204

def test_update_course():
    test_course_id = 2
    test_updated_data = {
        "course_name": "Updated Course Name",
        "university": "Updated University",
        "difficulty_level":"updated difficulty level",
        "course_description": "updated course description",
        "skills":"updated skills"
    }

    # Send a PUT request to update a course by ID
    response = requests.put(f"{BASE_URL}update/course/{test_course_id}", json=test_updated_data)

    # Check if the request was successful (status code 200)
    assert response.status_code == 200

    # Add more assertions based on your expected response format
    response_json = response.json()
    print(response_json)


