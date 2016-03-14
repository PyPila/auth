from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType

from authclient import admin

admin.site.register(User)
admin.site.register(Group)
admin.site.register(Permission)
admin.site.register(ContentType)
