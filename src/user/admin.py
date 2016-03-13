from django.contrib.auth.models import User, Group

from authclient import admin

admin.site.register(User)
admin.site.register(Group)
