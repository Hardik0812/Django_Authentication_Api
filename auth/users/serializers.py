from rest_framework import serializers
from users.models import User

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