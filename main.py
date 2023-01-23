'''
This is the demo for Oauth2 authentication with Password, client credentials, Authentication code flow

Author: Sheik Azarudeen <sheik.azarudeen@galaxyweblinks.co.in>
'''

from fastapi import FastAPI, Depends, status, Form, Request, Query
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.exceptions import HTTPException, RequestValidationError
from tortoise.contrib.fastapi import register_tortoise
from passlib.hash import bcrypt
from typing import Optional
import secrets
from datetime import datetime, timedelta
import time
from fastapi.templating import Jinja2Templates
import jwt
import random
from decouple import config
from token_validate import *


templates = Jinja2Templates(directory="templates")

app = FastAPI()
    

@app.post('/create_user')
async def create_user(user: userIn_pydantic) -> JSONResponse:
    '''
    Create a new user
    
    Parameters
    User pydantic model
    
    Returns
    json object
    '''
    client_id = secrets.token_urlsafe(32)
    client_secret = secrets.token_urlsafe(32)
    user_obj = User(username = user.username, password = bcrypt.hash(user.password), client_id = client_id, client_secret = client_secret, redirect_url = user.redirect_url)
    await user_obj.save()
    return {"username": user.username, "client_id": client_id, "client_secret": client_secret, "message": "User saved successfully"}

@app.post('/add_scope')
async def add_scope(scopes: scopesIn_pydantic) -> JSONResponse:
    '''
    add a new scope
    
    Parameters
    Scope pydantic model
    
    Returns
    json object
    '''
    scope = scopes.scope
    
    scopes_obj = Scopes(scope = scope)
    await scopes_obj.save()
    return {"scope": scope, "message": "Scope saved successfully"}


@app.post("/token")
async def token(form_data: OAuth2AuthenticationRequestForm = Depends()):
    '''
    Generate a access token here. Should verify User credentials or client credentials
    before generating a access token
    
    Parameters: 
    client ID, client secret key, username, password, grant_type, scope, state
    
    Returns:
    Access token
    '''
    
    if form_data.grant_type == 'password':
        details = "Incorrect username or password"
    elif form_data.grant_type in ['client_credentials','authorization_code']:
        details = "Incorrect client id and client secret key"
    elif form_data.grant_type == 'refresh_token':
        details = "Invalid refresh token"
        
    failed_auth = HTTPException(
        status_code=400, detail = details
    )
    
    if form_data.grant_type != 'refresh_token':
        user, auth_code, error = await authenticateUser(form_data) 
        if user == False and not error:
            raise failed_auth
        
        if error:
            raise HTTPException(status_code=400, detail = error['error'])
        
        user_details = dict(user)
        grant_type = form_data.grant_type
    else:
        if not form_data.refresh_token:
            await __raiseRequiredError("refresh_token")
            
        token_validate_status, info = await TokenValidator.validate_refresh_token(form_data.refresh_token)
        if not token_validate_status:
            raise failed_auth
        user_details = {
        'username': info['username'],
        'client_id': info['client_id'],
        'id': info['user_id'],
        }
        form_data.scopes = info['scopes']
        form_data.grant_type = info['grant_type']
        grant_type = 'refresh_token'
        auth_code = None
            
    date_now = int(time.time())
    expires_in = random.randint(3300,3600)
    access_token_expires_date = date_now + expires_in # Add random seconds for expiry date between 55 minutes to 60 minutes.
    refresh_token_expires_date = int(datetime.timestamp(datetime.strptime(datetime.fromtimestamp(date_now).strftime("%Y-%m-%d %H:%M:%S"),"%Y-%m-%d %H:%M:%S") + timedelta(days=15))) # set to 15 days from now
    refresh_token_id = secrets.token_hex(16)
    
    # we defined scope. Should validate scope here before generating access token
    access_token_payload = {
                            'aud': JWT_AUDIENCE, # JWT claim don't change this key
                            'iss': JWT_ISSUER, # JWT claim don't change this key
                            'iat': date_now, # JWT claim don't change this key
                            'nbf': date_now, # JWT claim don't change this key
                            'exp': access_token_expires_date, # JWT claim don't change this key
                            'username': user_details['username'],
                            'client_id':user_details['client_id'], 
                            'scope': form_data.scopes if form_data.scopes and auth_code is None else auth_code.scope, 
                            'app_name': 'mctppeOauth2', # it should be change dynamically as per user's app name
                            'app_id': '123456', # it should be change dynamically as per user's app ID
                            'amr': form_data.grant_type if isinstance(form_data.grant_type, list) else [form_data.grant_type], # JWT claim don't change this key
                            'sub': bcrypt.hash(user_details['username']),
                            'ver': '1.0',
                            'type': 'access_token'
                            }
    
    access_token = jwt.encode(access_token_payload, JWT_PRIVATE_KEY, algorithm = JWT_ALGORITHM)
    
    
    refresh_toke_payload = {
                            'aud': JWT_AUDIENCE, # JWT claim don't change this key
                            'iss': JWT_ISSUER, # JWT claim don't change this key
                            'iat': date_now, # JWT claim don't change this key
                            'nbf': date_now, # JWT claim don't change this key
                            'exp': refresh_token_expires_date, # JWT claim don't change this key
                            'username': user_details['username'],
                            'client_id':user_details['client_id'], 
                            'scope': form_data.scopes if form_data.scopes and auth_code is None else auth_code.scope, 
                            'amr': [form_data.grant_type], # JWT claim don't change this key
                            'sub': bcrypt.hash(user_details['username']),
                            'jti': refresh_token_id,
                            'type': 'refresh_token'
                        }
    refresh_token = jwt.encode(refresh_toke_payload, JWT_PRIVATE_KEY, algorithm = JWT_ALGORITHM)
    
    await User_refresh_tokens(user_id = user_details['id'], refresh_token_id = refresh_token_id, validate_status = 0).save()
    
    access_token_response = {
            "scope": form_data.scopes or auth_code.scope,
            "token_type": "bearer", 
            "access_token": access_token,  
            "expires_in": expires_in, 
            "refresh_token": refresh_token, 
            "token_created_date": datetime.fromtimestamp(date_now).strftime("%Y-%m-%d %H:%M:%S")
            }
    if form_data.state: 
        access_token_response["state"] = form_data.state
    
    if grant_type == "refresh_token":
        await User_refresh_tokens.filter(user_id = user_details['id'], refresh_token_id = info['jti']).update(validate_status = 1)
    return access_token_response

async def authenticateUser(form_data) -> bool:
    '''
    Verify the user credentials. Here we can check all possible OAuth flows.
    
    Parameters:
    form_data
    
    Returns:
    Boolean|exception 
    '''
    if form_data.grant_type == 'password':
        return await __passwordAuthenticate(form_data)
    
    elif form_data.grant_type == 'client_credentials':
        return await __clientCredentialsAuthenticate(form_data)
    
    elif form_data.grant_type == 'authorization_code':
        return await __authorizationCodeAuthentication(form_data)


async def __passwordAuthenticate(form_data):
    '''
    Check username and password for Password authentication flow
    
    Parameter
    Object
    
    Return
    Tuple|Exception
    '''
    if form_data.username and form_data.password:
        #check username
        try:
            user = await User.get(username = form_data.username)
        except Exception:
            return (False, None, None)
        
        #check username and password
        if not user or not bool(user.verify_password(form_data.password)):
            return (False, None, None)
        
        #validate scope
        validate_status, error = await __validateScopes(form_data)
        return (user, None, None) if validate_status else (False, None, error)
        
    # if username or password missing
    await __raiseRequiredError("password" if form_data.username else "username")
    
async def __clientCredentialsAuthenticate(form_data):
    '''
    Check client id and client secret for Client Credentials flow
    
    Parameter
    Object
    
    Return
    Tuple|Exception
    '''
    if form_data.client_id and form_data.client_secret:
        try:
            user = await User.get(client_id = form_data.client_id, client_secret = form_data.client_secret)
        except Exception:
            return (False, None, None)
        if [form_data.client_id, form_data.client_secret] != [user.client_id, user.client_secret]:
            return (False, None, None)
    
        #validate scope
        validate_status, error = await __validateScopes(form_data)
        return (user, None, None) if validate_status else (False, None, error)  
    
    #if client id or client secret missing
    await __raiseRequiredError("Client Secret Key" if form_data.client_id else "Client ID")
        

async def __authorizationCodeAuthentication(form_data):
    if form_data.client_id and form_data.client_secret:
        
        # check client id and client secret
        try:
            user = await User.get(client_id = form_data.client_id, client_secret = form_data.client_secret) #
        except Exception as e:
            return False, None, None
        
        
        # continue if client id & client secret
        # check auth code is valid with scope
        try:
            auth_code = await User_auth_codes.get(user_id = user.id, auth_code = form_data.code, validate_status = 0)  
        except Exception as e:
            print(e)
            details = [{"loc": 
                    [
                        "body",
                        "code",
                    ],
                    "msg": "Authentication code mismatch or invalid scope posted or code already used",
                    "type": "value_error"
                    }
                    ]
            raise HTTPException(status_code = status.HTTP_422_UNPROCESSABLE_ENTITY, detail = details) from e
        
        
        # If user give auth code after 10 minutes, should raise this exception
        daysDiff = (datetime.strptime(datetime.strftime(datetime.now(), '%Y-%m-%d %H:%M:%S'),'%Y-%m-%d %H:%M:%S') - datetime.strptime(datetime.strftime(auth_code.created_date, '%Y-%m-%d %H:%M:%S'),'%Y-%m-%d %H:%M:%S')).total_seconds() / 60.0
        if daysDiff > 10:
            await User_auth_codes.filter(user_id = user.id, auth_code = form_data.code, scope = " ".join(form_data.scopes), validate_status = 0).update(validate_status= 1)
            details = [{"loc": 
                    [
                        "body",
                        "code",
                    ],
                    "msg": "Authentication code expired",
                    "type": "value_error"
                    }
                    ]
            raise HTTPException(status_code = status.HTTP_422_UNPROCESSABLE_ENTITY, detail = details) 
        await User_auth_codes.filter(user_id = user.id, auth_code = form_data.code, validate_status = 0).update(validate_status= 1)
        return user, auth_code, None
    await __raiseRequiredError("client_secret" if form_data.client_id else "client_id")

async def __raiseRequiredError(message):
    '''
    Raise required exception
    
    Parameters
    message
    
    Return
    HTTP Exception
    '''
    details = [{"loc": 
                    [
                        "body",
                        message
                    ],
                    "msg": "field required",
                    "type": "value_error.missing"
                    }
                    ]
    raise HTTPException(status_code = 422, detail = details)
    
async def __validateScopes(form_data):
    '''
    Validate scopes.
    obj param is Optional. If obj passed 
    
    Parameters
    Form data Object, Object
    
    Return
    Tuple
    '''
    #check scope
    if form_data.scopes:
        user_scopes_list = form_data.scopes.split()
        try:
            scope_list = await Scopes.filter(scope__in = user_scopes_list).all()
            if not scope_list:
                return(False, {'error':f"The asked {form_data.scopes} scope(s) does not exist."})
            db_scopes = {i.scope for i in scope_list}
            mis_matched_scopes = {x for x in user_scopes_list if x not in db_scopes}
            if mis_matched_scopes:
                mis_matched_scopes_str = " ".join(mis_matched_scopes)
                return(False, {'error':f"The asked {mis_matched_scopes_str} scope(s) does not exist."})
            return (True, None)
        except Exception as e:
            raise HTTPException(status_code=400, detail = f"The asked {form_data.scopes} scope(s) does not exist.") from e 
    await __raiseRequiredError("scope")

@app.get('/authorize', response_class=HTMLResponse)
async def authorize(request: Request, client_id:str, redirect_uri:str, scope: str, response_type:str, state:str = "") -> HTMLResponse:
    '''
    Here we should redirect to login page. After successful login return the auth code
    ''' 
    return templates.TemplateResponse("login.html", {"request": request, "auth_code": {'response_type':response_type, 'client_id': client_id, 'redirect_uri': redirect_uri, 'scope': scope, 'state': state,'post_url': '/oauthdemo/login' if config('environment') == 'development' else "/login"}})


@app.post("/login")
async def login(form_data: LoginForm = Depends(LoginForm.as_form)):
    '''
    User login
    
    Parameters
    username, password
    
    Returns
    Boolean
    '''    

    try:
        
        user = await User.get(username = form_data.username)
    except Exception as e:
        raise HTTPException(status_code=400, detail = "Incorrect username or password") from e
    
    if not user or not bool(user.verify_password(form_data.password)):
        raise HTTPException(status_code=400, detail = "Incorrect username or password")
    
    # if valid user continue to check other things
    # check client ID
    try:
        user = await User.get(client_id = form_data.client_id, id=user.id)
    except Exception as e:
        exception = 'error_description=Client ID does not match.'
        response = f'{form_data.redirect_uri}?error=client_id_not_match&{exception}'
        return RedirectResponse(response, status_code=303)  
    
    #check response type
    if form_data.response_type != 'code':
        exception = 'error_description=The application requested an unsupported response type when requesting a token'
        response = f'{form_data.redirect_uri}?error=unsupported_response_type&{exception}'
        return RedirectResponse(response, status_code=303)  
    
    
    # check redirect uri with app
    try:
        await User.get(redirect_url = form_data.redirect_uri, client_id = form_data.client_id)
    except Exception as e:
        raise HTTPException(
            status_code=400, detail = "The redirect URI specified in the request does not match the redirect URIs configured for the application"
        ) from e 
    
    # #check scope
    user_scopes_list = form_data.scope.split()
    try:
        scope_list = await Scopes.filter(scope__in = user_scopes_list).all()
        if not scope_list:
            exception = f"error_description=The asked {form_data.scope} scope(s) does not exist."
            response = f'{form_data.redirect_uri}?error=invalid_scope&{exception}'
            return RedirectResponse(response, status_code=303)  
        
        matched_scopes = {i.scope for i in scope_list}
        mis_matched_scopes = {x for x in user_scopes_list if x not in matched_scopes}
        if mis_matched_scopes:
            exception = f"error_description=The asked {' '.join(mis_matched_scopes)} scope(s) does not exist."
            response = f'{form_data.redirect_uri}?error=invalid_scope&{exception}'
            return RedirectResponse(response, status_code=303) 

    except Exception as e:
        exception = f"error_description=The asked {form_data.scope} scope(s) does not exist."
        response = f'{form_data.redirect_uri}?error=invalid_scope&{exception}'
        return RedirectResponse(response, status_code=303)  
        
    
    '''
    we should save this code in the DB. In the next step the user will request the access token
    along with the authorization code
    '''
    auth_code = secrets.token_urlsafe(64)
    
    # Here we should check the redirection URL. This should be matched with the user's given URLs while creating an app. It does not match should raise the exception
    response = f'{form_data.redirect_uri}?code={auth_code}{f"&state={form_data.state}" if form_data.state else ""}'
    auth_obj = User_auth_codes(user_id = user.id, auth_code = auth_code, scope = ''.join(form_data.scope), validate_status = 0, created_date = datetime.now())
    await auth_obj.save()
    return RedirectResponse(response, status_code=303)  
    
    
    

@app.get('/oauth_code_redirect')
async def oauth_code_redirect(code: Optional[str] = "", state: Optional[str] = None, error: Optional[str] = None, error_description: Optional[str] = None):
    '''
    This is sample redirect url page for showing authentication code
    '''
    code_response = {'authorization_code': code}
    if state:
        code_response['state'] = state or ""
    return {'error': error, 'error_description': error_description} if error else code_response
    #return True

    
validate_user = TokenValidator(scope=['profile_read']) # Create a object for token validator with required scopes
@app.get('/profile/me', response_model = ProfileModel)
async def get_user_profile(user = Depends(validate_user)):
    if user:
        return user

    
register_tortoise(
    app,
    db_url ='sqlite://db.sqlite3',
    modules ={"models":['main']},
    generate_schemas = True,
    add_exception_handlers = True
)