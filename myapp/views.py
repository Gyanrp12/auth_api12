from django.shortcuts import render

from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from django.contrib.auth.models import AbstractBaseUser
from .serializers import UserSerializer
from .models import User
import jwt,datetime
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
 
class RegisterView(APIView):
    def post(self,request):
        ser = UserSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response({'msg':"successs"})


class LoginView(APIView):
    def post(self,request):
        email = request.data['email']
        password = request.data['password']
        # print("-----------------------------",email)
        
        # usr = User.objects.get(email=email)
        # print(usr.password)
        user = authenticate(email=email,password=password)
        print("----------------",password)
        if user is not None :
            token = get_tokens_for_user(user)
            print("+++++++++++++++",token)
            response = Response()
            response.set_cookie(key='jwt', value=token)
            response.data = {
                'jwt': token
           
            }
            print("+++++++++++++++",token)
            return response
        return Response({'msg':"errors"})

class UserView(APIView):
    # permissions_classes = [IsAuthenticated]
    def get(self, request):
        token = request.COOKIES.get('jwt')
        print("++++++++++++++++++",token)
        if not token:
            return Response({'msg':'error'})
        else:
            payload = jwt.decode(token,'secret',algorithms=['HS256'])
            user = User.objects.filter(id=payload['id']).first()
            ser = UserSerializer(user)

            return Response(ser.data)    
    
class LogoutView(APIView):
    def post(self, request):
     
        response = Response()
        response.delete_cookie('jwt')
        response.data={
            'msg':'Success'
            
        }
        print("+++++++++++++++++++++++++++")
        return response