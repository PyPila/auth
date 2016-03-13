from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from user.serializers import (
    PasswordJSONWebTokenSerializer, RefreshJSONWebTokenSerializer,
)


class BaseAuthAPIView(APIView):

    permission_classes = ()
    authentication_classes = ()

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            return Response(
                {'resource_token': serializer.validated_data.get('token')},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordAuthAPIView(BaseAuthAPIView):

    serializer_class = PasswordJSONWebTokenSerializer


class RefreshJSONWebToken(BaseAuthAPIView):
    serializer_class = RefreshJSONWebTokenSerializer
