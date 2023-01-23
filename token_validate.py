'''
This the access token validator class

Author: Sheik Azarudeen <sheik.azarudeen@galaxyweblinks.co.in>
'''
import jwt
from fastapi import Depends
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, OAuth2AuthorizationCodeBearer
from custom_oauth2.custom_oauth2 import Oauth2ClientCredentials, OAuth2AuthenticationRequestForm
from decouple import config
from typing import Optional, Union, List
from passlib.hash import bcrypt
from models import *

JWT_SECRET = config('secret')
JWT_ALGORITHM = config('algorithm')
JWT_AUDIENCE = config('audience')
JWT_ISSUER = config('issuer')
JWT_PRIVATE_KEY = open(config('private_key')).read()
JWT_PUBLIC_KEY = open(config('public_key')).read()
REFRESH_PRIVATE_KEY = config('refresh_private_key')
REFRESH_PUBLIC_KEY = config('refresh_public_key')


#simple way to say where to create a access token
client_credential_scheme = Oauth2ClientCredentials(tokenUrl='token')

class TokenValidator:
    '''
    Class for validate the access token
    '''
    def __init__(self, scope: Optional[Union[List[str],str]] = None) -> None:
        '''
        Parameters
        Scope value is List | str | optional
        string should be space separated
        
        Returns
        None
        '''
        self.scope = scope

    async def __call__(self, token: str = Depends(client_credential_scheme)):
        try:
            access_token_payload = jwt.decode(
                        token, 
                        JWT_PUBLIC_KEY, 
                        audience = JWT_AUDIENCE, 
                        algorithms = [JWT_ALGORITHM], 
                        issuer = JWT_ISSUER
                        )
            
            # validate the username and subject
            username = access_token_payload.get('username')
            if username and bcrypt.verify(username, access_token_payload.get('sub')) != True:
                raise HTTPException(status_code=400, detail = "Username does not match") 
            
            #check username and client ID
            try:
                user = await User.get(username = username, client_id = access_token_payload.get('client_id'))
            except Exception as e:
                raise HTTPException(status_code=400, detail = "Username and Client ID does not match") from e
            
            
            # validate the scope
            scope = access_token_payload.get('scope')
            required_scope = self.scope
            if isinstance(self.scope, str):
                required_scope = self.scope.split()
            if all(_ in scope for _ in required_scope):
                return {"username": user.username, "client_id": user.client_id}
            else:
                raise HTTPException(status_code=400, detail = "Access denied.")
            
        except jwt.ExpiredSignatureError as e:
            raise HTTPException(status_code=400, detail = "Access token has expired") from e
        except jwt.InvalidSignatureError as e:
            raise HTTPException(status_code=400, detail = str(e)) from e
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=400, detail = "Invalid Access token") from e
        
    @staticmethod
    async def validate_refresh_token(refresh_token):
        try:
            refresh_token_payload = jwt.decode(
                        refresh_token, 
                        JWT_PUBLIC_KEY, 
                        audience = JWT_AUDIENCE, 
                        algorithms = [JWT_ALGORITHM], 
                        issuer = JWT_ISSUER
                        )
            
            
            # validate the username and subject
            username = refresh_token_payload.get('username')
            if username and bcrypt.verify(username, refresh_token_payload.get('sub')) != True:
                raise HTTPException(status_code=400, detail = "Invalid Refresh Token") 
            
            #check username and client ID
            try:
                client_id = refresh_token_payload.get('client_id')
                user = await User.get(username = username, client_id = client_id)
            except Exception as e:
                raise HTTPException(status_code=400, detail = "Invalid Refresh Token") from e
            
            #check jti. Refresh token should be one time valid
            try:
                jti = refresh_token_payload.get('jti')    
                await User_refresh_tokens.get(refresh_token_id = jti, user_id = user.id, validate_status = 0)
            except Exception as e:
                raise HTTPException(status_code=400, detail = "Refresh Token already used.") from e
            
            
            #we can validate app id
            # app_id = access_token_payload.get('app_id')
            
            
            return True, {'username': username, 'client_id': client_id, 'scopes': refresh_token_payload.get('scope'), 'grant_type': refresh_token_payload.get('amr'), 'user_id': user.id,'jti':jti}
            
        except jwt.ExpiredSignatureError as e:
            raise HTTPException(status_code=400, detail = "Refresh token has expired") from e
        except jwt.InvalidSignatureError as e:
            raise HTTPException(status_code=400, detail = str(e)) from e
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=400, detail = "Invalid Refresh token") from e