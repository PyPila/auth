from django.conf.urls import url

from user import views


urlpatterns = [
    url(
        r'password/$', views.PasswordAuthAPIView.as_view(),
        name='password-auth'
    ),
    # url(
    #     r'token/$', views.TokenAuthAPIView.as_view(),
    #     name='token-auth'
    # ),
    # url(
    #     r'oauth/$', views.OAuthAPIView.as_view(),
    #     name='oauth-auth'
    # ),
    # url(
    #     r'oauth/(?P<client_id>\w+)/$', views.OAuthView.as_view(),
    #     name='oauth-login'
    # ),
]
