## Table of Contents

- [Installation](#installation)
- [Endpoints](#endpoints)
  - [1. Upsert user](#1-upsert-user)
  - [2. Login user](#2-login-an-existing-user)
  - [3. Create a new user](#3-create-a-new-user)

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/blabla.git
    cd your-repository
    ```

2. Install the required packages (you could do that inside a venv):

    ```bash
    pip install -r requirements.txt
    ```

3. Apply migrations:

    ```bash
    python manage.py migrate
    ```

4. Run the development server:

    ```bash
    python manage.py runserver
    ```

## Endpoints

### 1. Upsert User

- **URL:** `/users/`
- **Method:** `PUT`
- **Description:** Upsert user by providing the google firebase token.
- **Token:**
  - `firebase_access_token` (string): User's firebase token.
- **Response:**
  - Status 200: User retrieved successfully.
  - Status 201: User created successfully.
  - Status 400: User upsert failed.

### 2. Login an Existing User

- **URL:** `/users/auth/sign-in/`
- **Method:** `POST`
- **Description:** Login an existing user by providing the required fields.
- **Request Body:**
  - `email` (string): User's email address.
  - `password` (string): User's password.
- **Response:**
  - Status 200: User logged in successfully.
  - Status 404: User does not exist.

### 3. Create a New User

- **URL:** `/users/auth/sign-up/`
- **Method:** `POST`
- **Description:** Create a new user by providing the required fields.
- **Request Body:**
  - `email` (string): User's email address.
  - `password` (string): User's password.
- **Response:**
  - Status 201: User created successfully.
  - Status 400: User creation failed.