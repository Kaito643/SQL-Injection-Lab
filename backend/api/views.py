from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from django.db import connection
from django.shortcuts import render
from django.contrib.auth.models import User
from rest_framework import generics
from .serializers import UserSerializer, NoteSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Note
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import logging

logger = logging.getLogger(__name__)


class NoteListCreate(generics.ListCreateAPIView):
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Note.objects.filter(author=user)

    def perform_create(self, serializer):
        if serializer.is_valid():
            serializer.save(author=self.request.user)
        else:
            print(serializer.errors)


class NoteDelete(generics.DestroyAPIView):
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Note.objects.filter(author=user)


class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

class CustomLoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        # Check if username and password are provided
        if not username or not password:
            return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Manually query the database using raw SQL
            with connection.cursor() as cursor:
                cursor.execute("SELECT id, username, password FROM auth_user WHERE username = %s", [username])
                user = cursor.fetchone()

            if user:
                user_id, db_username, db_password = user

                # Check if the provided password matches the hashed password in the database
                if check_password(password, db_password):
                    # Generate JWT tokens manually
                    try:
                        user_instance = User.objects.get(id=user_id)
                        refresh = RefreshToken.for_user(user_instance)
                        return Response({
                            "refresh": str(refresh),
                            "access": str(refresh.access_token),
                        })
                    except User.DoesNotExist:
                        logger.error(f"User with ID {user_id} does not exist.")
                        return Response({"error": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
                else:
                    return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return Response({"error": "An internal server error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)