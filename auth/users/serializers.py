from .utils import *
from django.forms import ValidationError
from rest_framework import serializers
from users.models import User
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ('name','email','password','password2')
        extra_kwargs ={
            'password':{'write_only':True}
        }
# validate password
    def validate(self,attrs):
        password =attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password do not match")
        return attrs

    def create(self,validate_data):
        return User.objects.create_user(**validate_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields =['email', 'password']
    
class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255,write_only=True)
    password2 = serializers.CharField(max_length=255,write_only=True)
    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, obj):
        password = obj.get('password')
        password2 = obj.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("password do not match")
        user.set_password(password)
        user.save()
        return obj

class SentEmailResetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=225)
    class Meta:
        model = User
        fields = ['email']
    
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = 'http://127.0.0.1:8000/authapi/resetpassword/'+uid+'/'+token

            #send email
            body = 'Click link to reset password' +link
            data = {
                
                'subject':"Reset Password",
                'body':body,
                'to_email':user.email

            }
            Util.send_mail(data)
 
            return attrs
        else:
            raise ValidationError('You are not Register user')
        
class UserPasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255,write_only=True)
    password2 = serializers.CharField(max_length=255,write_only=True)
    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, obj):
        try:
            password = obj.get('password')
            password2 = obj.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError("password do not match")
            id = smart_str(urlsafe_base64_encode(uid))
            user = User.objects.get(id = id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise serializers.ValidationError("Token is not valid or expired")
        
            user.set_password(password)
            user.save()
            return obj
        except DjangoUnicodeDecodeError:
            PasswordResetTokenGenerator().check_token(user,token)

        
