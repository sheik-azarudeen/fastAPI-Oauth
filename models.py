from fastapi import Form, Query
from pydantic import BaseModel
from tortoise.models import Model
from typing import Union, Optional, List
from tortoise import fields
from tortoise.contrib.pydantic import pydantic_model_creator
from passlib.hash import bcrypt

class User(Model):
    '''
    User tortoise model class
    '''
    id: Optional[int] = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password = fields.CharField(150)
    client_id: Optional[str] = fields.CharField(255)
    client_secret: Optional['str'] = fields.CharField(255)
    redirect_url: Optional['str'] = fields.TextField()
            
    def verify_password(self, password):
        return bcrypt.verify(password, self.password)
    
        
userIn_pydantic = pydantic_model_creator(User, name = 'UserIN', exclude_readonly = True)

class User_auth_codes(Model):
    '''
    User's authorization code for Oauth2 authorization code flow
    '''
    id: Optional[int] = fields.IntField(pk=True)
    user_id = fields.IntField()
    auth_code = fields.CharField(255, unique=True)
    scope = fields.CharField(255)
    validate_status = fields.IntField()
    created_date = fields.DatetimeField(auto_now_add=True)

UserAuthCodeIn_pydantic = pydantic_model_creator(User_auth_codes, name = 'UserAuthCodeIn', exclude_readonly = True)

class User_refresh_tokens(Model):
    '''
    User's refresh token id saved here
    To validate refresh token. Should use refresh token only one time
    '''
    id: Optional[int] = fields.IntField(pk=True)
    user_id = fields.IntField()
    refresh_token_id = fields.CharField(100, unique=True)
    validate_status  = fields.IntField()

UserRefreshToken_pydantic = pydantic_model_creator(User_refresh_tokens, name = 'UserRefreshToken', exclude_readonly = True)

class Scopes(Model):
    '''
    Scopes master table
    '''
    id: Optional[int] = fields.IntField(pk=True)
    scope = fields.CharField(100, unique=True)
    created_date = fields.DatetimeField(auto_now_add=True)

scopesIn_pydantic = pydantic_model_creator(Scopes, name = 'scopes', exclude_readonly = True)

class AccessTokenModel(BaseModel):
    '''
    Access token model class
    '''
    scope: Optional[str]
    token_type: str
    access_token: str
    refresh_token: str
    token_created_date: str
    expires_in: str
    state: Optional[str]
    

class LoginForm(BaseModel):
    '''
    Login form model class
    '''
    username: str
    password: str
    response_type: str
    client_id: str
    scope: str
    redirect_uri: str
    state: Optional[str]
    
    @classmethod
    def as_form(
        cls,
        username: str = Form(...),
        password: str = Form(...),
        response_type: str = Form(...),
        client_id: str = Form(...),
        scope: str = Form(...),
        redirect_uri: str = Form(...,regex="^(http|https)"),
        state: Optional[str] = Form("")
    ):
        return cls(username=username, password=password, response_type=response_type, client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state)


class ProfileModel(BaseModel):
    '''
    Profile response model class
    '''
    username: str
    client_id: str