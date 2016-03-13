from datetime import datetime, timedelta
from calendar import timegm

import jwt
from django.contrib.auth import authenticate, get_user_model
from django.conf import settings
from rest_framework import serializers


class JSONWebTokenSerializer(serializers.Serializer):

    def __init__(self, *args, **kwargs):
        super(JSONWebTokenSerializer, self).__init__(*args, **kwargs)

        self.make_fields()

    def make_fields(self):
        raise NotImplementedError()

    def get_credentials(self, attrs):
        raise NotImplementedError()

    def jwt_payload(self, user):

        payload = {
            'pk': user.pk,
            'username': user.get_username(),
            'is_superuser': user.is_superuser,
            'is_staff': user.is_staff,
            'exp': datetime.utcnow() + settings.AUTH_JWT_EXPIRATION_DELTA,
            'perms': list(user.get_all_permissions()),
        }

        if settings.AUTH_JWT_ALLOW_REFRESH:
            payload['orig_iat'] = timegm(
                datetime.utcnow().utctimetuple()
            )

        if settings.AUTH_JWT_AUDIENCE is not None:
            payload['aud'] = settings.AUTH_JWT_AUDIENCE

        if settings.AUTH_JWT_ISSUER is not None:
            payload['iss'] = settings.AUTH_JWT_ISSUER

        return payload

    def jwt_encode(self, payload):
        return jwt.encode(
            payload,
            settings.AUTH_JWT_PRIVATE_KEY,
            settings.AUTH_JWT_ALGORITHM
        ).decode('utf-8')

    def validate(self, attrs):
        credentials = self.get_credentials(attrs)

        if all(credentials.values()):
            user = authenticate(**credentials)

            if user:
                if not user.is_active:
                    raise serializers.ValidationError(
                        'User account is disabled.'
                    )

                payload = self.jwt_payload(user)

                return {
                    'token': self.jwt_encode(payload),
                    'user': user
                }
            else:
                raise serializers.ValidationError(
                    'Unable to login with provided credentials.'
                )
        else:
            raise serializers.ValidationError('Invalid credentials.')


class PasswordJSONWebTokenSerializer(JSONWebTokenSerializer):

    @property
    def username_field(self):
        return get_user_model().USERNAME_FIELD

    def make_fields(self):
        self.fields[self.username_field] = serializers.CharField()
        self.fields['password'] = serializers.CharField(write_only=True)

    def get_credentials(self, attrs):
        return {
            self.username_field: attrs.get(self.username_field),
            'password': attrs.get('password')
        }


class RefreshJSONWebTokenSerializer(JSONWebTokenSerializer):
    """
    Refresh an access token.
    """

    token = serializers.CharField()

    def make_fields(self):
        pass

    def get_credentials(self, attrs):
        pass

    def jwt_decode(self, token):
        options = {
            'verify_exp': settings.AUTH_JWT_VERIFY_EXPIRATION,
        }

        return jwt.decode(
            token,
            settings.AUTH_JWT_PUBLIC_KEY,
            settings.AUTH_JWT_VERIFY,
            options=options,
            leeway=settings.AUTH_JWT_LEEWAY,
            audience=settings.AUTH_JWT_AUDIENCE,
            issuer=settings.AUTH_JWT_ISSUER,
            algorithms=[settings.AUTH_JWT_ALGORITHM]
        )

    def _check_payload(self, token):
        try:
            payload = self.jwt_decode(token)
        except jwt.ExpiredSignature:
            msg = 'Signature has expired.'
            raise serializers.ValidationError(msg)
        except jwt.DecodeError:
            msg = 'Error decoding signature.'
            raise serializers.ValidationError(msg)

        return payload

    def _check_user(self, payload):
        username = payload['username']

        if not username:
            msg = 'Invalid payload.'
            raise serializers.ValidationError(msg)

        user_model = get_user_model()

        try:
            user = user_model.objects.get_by_natural_key(username)
        except user_model.DoesNotExist:
            msg = 'User doesn\'t exist.'
            raise serializers.ValidationError(msg)

        if not user.is_active:
            msg = 'User account is disabled.'
            raise serializers.ValidationError(msg)

        return user

    def validate(self, attrs):
        token = attrs['token']

        payload = self._check_payload(token=token)
        user = self._check_user(payload=payload)
        orig_iat = payload.get('orig_iat')

        if orig_iat:
            refresh_limit = settings.AUTH_JWT_REFRESH_EXPIRATION_DELTA

            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 +
                                 refresh_limit.seconds)

            expiration_timestamp = orig_iat + int(refresh_limit)
            now_timestamp = timegm(datetime.utcnow().utctimetuple())

            if now_timestamp > expiration_timestamp:
                msg = 'Refresh has expired.'
                raise serializers.ValidationError(msg)
        else:
            msg = 'orig_iat field is required.'
            raise serializers.ValidationError(msg)

        new_payload = self.jwt_payload(user)
        new_payload['orig_iat'] = orig_iat

        return {
            'token': self.jwt_encode(new_payload),
            'user': user
        }
