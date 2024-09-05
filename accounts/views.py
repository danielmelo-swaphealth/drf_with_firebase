from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .models import User
from .serializers import UserSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import AllowAny, IsAuthenticated
from .firebase_auth.firebase_authentication import FirebaseAuthentication
from .firebase_auth.firebase_authentication import auth as firebase_admin_auth
from .utils.custom_email_verification_link import generate_custom_verification_link
from django.contrib.auth.hashers import check_password
import re
from drf_with_firebase.settings import auth
from accounts.firebase_auth.firebase_authentication import auth as firebase_admin_auth


class AuthCreateNewUserView(APIView):
    """
    API endpoint to create a new user.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    @swagger_auto_schema(
        operation_summary="Create a new  user",
        operation_description="Create a new user by providing the required fields.",
        tags=["User Management"],
        request_body=UserSerializer,
        responses={201: UserSerializer(many=False), 400: "User creation failed."}
    )
    def post(self, request, format=None):
        data = request.data
        email = data.get('email')
        password = data.get('password')
        
        included_fields = [email, password]
        # Check if any of the required fields are missing
        if not all(included_fields):
            bad_response = {
                "status": "failed",
                "message": "All fields are required."
            }
            return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if email is valid
        if email and not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            bad_response = {
                "status": "failed",
                "message": "Enter a valid email address."
            }
            return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if password is less than 8 characters
        if len(password) < 8:
            bad_response = {
                "status": "failed",
                "message": "Password must be at least 8 characters long."
            }
            return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)
        # Check if password contains at least one uppercase letter, one lowercase letter, one digit, and one special character
        if password and not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]).{8,}$', password):
            bad_response = {
                "status": "failed",
                "message": "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character."
            }
            return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # create user on firebase
            user = auth.create_user_with_email_and_password(email, password)
            # create user on django database
            uid = user['localId']
            data["firebase_uid"] = uid
            data["is_active"] = True

            # sending custom email verification link
            try:
                verify_link = generate_custom_verification_link(email)
            except Exception as e:
                # delete user from firebase if email verification link could not be sent
                firebase_admin_auth.delete_user(uid)
                bad_response = {
                    "status": "failed",
                    "message": 'Email verification link could not be sent; Please try again.'
                }
                return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)
        
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                response = {
                    "status": "success",
                    "message": f"User created successfully. Link to verify account: {verify_link}",
                    "data": serializer.data
                }
                return Response(response, status=status.HTTP_201_CREATED)
            else:
                auth.delete_user_account(user['idToken'])
                bad_response = {
                    "status": "failed",
                    "message": "User signup failed.",
                    "data": serializer.errors
                }
                return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)
           
        except Exception as e:
            bad_response = {
                "status": "failed",
                "message": str(e)
            }
            return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)


class AuthLoginExisitingUserView(APIView):
    """
    API endpoint to login an existing user.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    @swagger_auto_schema(
        operation_summary="Login an existing user",
        operation_description="Login an existing user by providing the required fields.",
        tags=["User Management"],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email of the user'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password of the user')
            }
        ),
        responses={200: UserSerializer(many=False), 404: "User does not exist."}
    )
    def post(self, request: Request):
        data = request.data
        email = data.get('email')
        password = data.get('password')

        try:
            user = auth.sign_in_with_email_and_password(email, password)
        except Exception:
            bad_response = {
                "status": "failed",
                "message": "Invalid email or password."
            }
            return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)

        extra_data = {
            "firebase_id": user['localId'],
            "firebase_access_token": user['idToken'],
            "firebase_refresh_token": user['refreshToken'],
            "firebase_expires_in": user['expiresIn'],
            "firebase_kind": user['kind']
        }
        try:
            existing_user = User.objects.get(email=email)
            
            # update password if it is not the same as the one in the database
            if not check_password(password, existing_user.password):
                existing_user.password = password
                existing_user.save()
            
            serializer = UserSerializer(existing_user)
            extra_data["user_data"] = serializer.data
        except User.DoesNotExist:
            extra_data["user_data"] = ""
        finally:
            response = {
                "status": "success",
                "message": "User logged in successfully.",
                "data": extra_data
            }
            return Response(response, status=status.HTTP_200_OK)


class UpsertUserView(APIView):
    """
    API endpoint to upsert user.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    @swagger_auto_schema(
        operation_summary="Upsert user",
        operation_description="Upsert user by providing the google firebase token.",
        tags=["User Management"],
        responses={200: UserSerializer(many=False), 201: UserSerializer(many=False), 400: "User upsert failed."}
    )
    def put(self, request: Request):
        try:
            user_firebase_access_token = request.META.get('HTTP_AUTHORIZATION').split(' ').pop()
            decode_access_token = firebase_admin_auth.verify_id_token(user_firebase_access_token)
            user_firebase_uid = decode_access_token.get('uid')
        except Exception:
            bad_response = {
                "status": "failed",
                "message": "Invalid authentication token provided."
            }
            return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = firebase_admin_auth.get_user(user_firebase_uid)
            existing_user = User.objects.get(email=user.email)
            serializer = UserSerializer(existing_user)
            response = {
                "status": "success",
                "message": "User retrieved successfully.",
                "data": serializer.data
            }
            return Response(response, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            data = {
                "firebase_uid": user.uid,
                "is_active": True,
                "email": user.email,
                "password": "random"
            }
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                response = {
                    "status": "success",
                    "message": "User saved in Django DB.",
                    "data": data
                }
                return Response(response, status=status.HTTP_201_CREATED)
            else:
                bad_response = {
                    "status": "failed",
                    "message": "Unable to save user in Django DB."
                }
                return Response(bad_response, status=status.HTTP_400_BAD_REQUEST)
