from multiprocessing import context
from rest_framework import status
from rest_framework.views import Response
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
# Create your views here.
from rest_framework_simplejwt.tokens import RefreshToken

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    def post(self, request,format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({"token":token,'msg':"Registration Success"},status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self, request,format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
    
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token,'msg':"Login Success"},status=status.HTTP_202_ACCEPTED)
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':"password changed successfully"},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        
class SentEmailResetPassword(APIView):
    def post(self, request,):
        serializers = SentEmailResetPasswordSerializer(data=request.data)
        serializers.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset link send.Please check your email'},status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
    def post(self,request,uid,token):
        serializers =UserPasswordResetSerializer(data = request.data,context={'uid':uid,'token':token})
        serializers.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset Successfully'},status=status.HTTP_200_OK)



    