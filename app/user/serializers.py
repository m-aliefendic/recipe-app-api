from django.contrib.auth  import get_user_model, authenticate
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user object"""

    class Meta:
        model = get_user_model()
        fields = ('email','password', 'name')
        extra_kwargs = {'password':{'write_only':True, 'min_length': 5}}

    def create(self, validated_data):
        """Create a new user with encrypted password and return it"""
        return get_user_model().objects.create_user(**validated_data)

class AuthTokenSerializer(serializers.Serializer):
    """Serializer  for the token authentication object"""
    email = serializers.CharField()
    password = serializers.CharField(
        style = {'input_type': 'passowrd'},
        trim_whitespace = False
    )

    def validate(self,attres):
        """Validate and  authenticate the user"""
        email= attres.get('email')
        password = attres.get('password')
        
        user = authenticate(
            request=self.context.get('request'),
            username= email,
            password= password
        )

        if not user:
            msg=_('Unable to authenticate with  provided credentials')
            raise serializers.ValidationError(msg, code='authentication')
        
        attres['user'] = user
        return attres
