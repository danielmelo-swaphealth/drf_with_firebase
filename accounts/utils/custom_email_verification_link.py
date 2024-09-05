from accounts.firebase_auth.firebase_authentication import auth as firebase_admin_auth
from django.core.mail import send_mail
from django.conf import settings


# create custom email verification link using celery background task
def generate_custom_verification_link(user_email):
    action_code_settings = firebase_admin_auth.ActionCodeSettings(
        url='https://toyproject-9c28d.firebaseapp.com/',
        handle_code_in_app=True,
    )
    return firebase_admin_auth.generate_email_verification_link(user_email, action_code_settings)
