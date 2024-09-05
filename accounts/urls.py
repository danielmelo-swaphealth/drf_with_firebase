from django.urls import path
from .views import (
    AuthCreateNewUserView,
    AuthLoginExisitingUserView,
    UpsertUserView
)

urlpatterns = [
    path('auth/sign-up/', AuthCreateNewUserView.as_view(), name='auth-create-user'),
    path('auth/sign-in/', AuthLoginExisitingUserView.as_view(), name='auth-login-drive-user'),
    path('', UpsertUserView.as_view(), name='upsert-user'),
]
