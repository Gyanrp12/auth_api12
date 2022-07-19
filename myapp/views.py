from django.conf import settings
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
from rest_framework_jwt.utils import jwt_decode_handler


# Create your views here.
from rest_framework_simplejwt.tokens import RefreshToken

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        # 'refresh': str(refresh),
        str(refresh.access_token),
    }
 
class RegisterView(APIView):
    def post(self,request):
        ser = UserSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response({'msg':"successs"})


class LoginView(APIView):
    def post(self,request):
        # ser = UserSerializer(data=request.data)
        # ser.is_valid()
        # email = request.data['email']
        # password = request.data['password']
        try:
                usr = User.objects.get(email= request.data['email'])
                try:
                    user = authenticate(email=request.data['email'],password=request.data['password'])
                    if user is not None :
                        token = get_tokens_for_user(usr)
                     
                        response = Response()
                        response.set_cookie(key='jwt', value=token)
                        response.set_cookie(key='id', value=user.id,expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'])
                        response.data = {
                            'jwt': token,
                
                       
                    
                        } 
                 
                        return response
                    else:
                        return Response({"msg":"password is incorrect"})
                except:
                    return Response({'msg':"errors"})
        except:
                return Response({'msg':"email is invalid"})

class UserView(APIView):
    # permission_classes  = [IsAuthenticated]
   
    def get(self, request):
        try:
            if request.COOKIES['id']  is not None:
                usr = User.objects.get(id=request.COOKIES['id'])
                ser = UserSerializer(usr)
                return Response(ser.data)
               
            else:
                return Response(ser.errors)
        except:
            return Response({"msg":"token is invalid"})
        # token = request.COOKIES['jwt']
        # print('payload'+ str(settings.SECRET_KEY))
        # try:
        #     token = request.COOKIES.get('jwt')
        #     print(token)
        #     payload = jwt.decode(token)
        #     user = User.objects.get(id=payload['user_id'])
        # except:
        #     return Response({"msg":"token is invalid"})
class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('id')
        response.delete_cookie('jwt')
        response.data={
            'msg':'logout'
            
 }

        return response
    
    
class DeleteView(APIView):
    def delete(self, request):
       if request.COOKIES['id']  is not None:
        usr = User.objects.get(id=request.COOKIES['id'])
        usr.delete()
        return Response({"msg":"deleted"})

class UpdateView(APIView):
        def put(self, request):
            try:
                if request.COOKIES['id'] is not None:
                    usr = User.objects.get(id=request.COOKIES['id'])
                    ser = UserSerializer(usr,data=request.data,partial=True)
                    ser .is_valid(raise_exception=True)
                    ser.save()
                    return Response({'msg':"updated"})
            except:
                return Response({'msg':"please first login"})
            
class AlluserView(APIView):
    def get(self, request):
        try:
            if request.COOKIES['jwt']is not None:
                usr = User.objects.all()
                print("-----------------------------",usr)
                ser = UserSerializer(usr,many=True)
                return Response(ser.data)
            
            else:
                return Response(ser.errors)
        except:
            return Response({"msg":"token is invalid"})