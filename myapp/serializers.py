from .models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField( 
           style={'input_type': 'password'},
           min_length=6, 
           max_length=68, 
           write_only=True)
    class Meta:
        model = User
        fields = ['id','username','email','password']
        
        #For hide the password
    

    #password hassing
    def create(self, validated_data):
        user = User(
        email=validated_data['email'],
        username=validated_data['username']
    )
        user.set_password(validated_data['password'])
        user.save()
        return user