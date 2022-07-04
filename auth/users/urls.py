from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from .views import *
urlpatterns = [
    #JWT
    path('access/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/token/', TokenRefreshView.as_view(), name='token_refresh'),

    #Api Endpoint
    path('register/',UserRegistrationView.as_view(), name='register'),
    path('login/',UserLoginView.as_view(), name='login'),
    path('changepassword/',ChangePasswordView.as_view(), name='changepassword'),
    path('resetpasswordemail/',SentEmailResetPassword.as_view(), name='resetpasswordemail'),
    path('resetpassword/<uid>/<token>/',UserPasswordResetView.as_view(), name='resetpassword'),


 ]
