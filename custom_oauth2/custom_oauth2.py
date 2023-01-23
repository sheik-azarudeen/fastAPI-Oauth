from typing import Dict, Optional
from fastapi.exceptions import HTTPException
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.param_functions import Form
from fastapi.security.utils import get_authorization_scheme_param
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

class OAuth2ClientCredentialsRequestForm:
    """
    Expect OAuth2 client credentials as form request parameters
    This is a dependency class, modeled after OAuth2PasswordRequestForm and similar.
    Use it like:
        @app.post("/login")
        def login(form_data: OAuth2ClientCredentialsRequestForm = Depends()):
            data = form_data.parse()
            print(data.client_id)
            for scope in data.scopes:
                print(scope)
            return data
    It creates the following Form request parameters in your endpoint:
    grant_type: the OAuth2 spec says it is required and MUST be the fixed string "client_credentials".
        Nevertheless, this dependency class is permissive and allows not passing it.
    scope: Optional string. Several scopes (each one a string) separated by spaces. Currently unused.
    client_id: optional string. OAuth2 recommends sending the client_id and client_secret (if any)
        using HTTP Basic auth, as: client_id:client_secret
    client_secret: optional string. OAuth2 recommends sending the client_id and client_secret (if any)
        using HTTP Basic auth, as: client_id:client_secret
    """

    def __init__(
        self,
        grant_type: str = Form(None, regex="^(client_credentials|refresh_token)$"),
        scope: str = Form(""),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
    ):
        self.grant_type = grant_type
        self.scopes = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret

class Oauth2ClientCredentials(OAuth2):
    """
    Implement OAuth2 client_credentials workflow.
    This is modeled after the OAuth2PasswordBearer and OAuth2AuthorizationCodeBearer
    classes from FastAPI, but sets auto_error to True to avoid uncovered branches.
    See https://github.com/tiangolo/fastapi/issues/774 for original implementation,
    and to check if FastAPI added a similar class.
    See RFC 6749 for details of the client credentials authorization grant.
    """
    
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(clientCredentials={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=True)
        
    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme_param = get_authorization_scheme_param(authorization)
        scheme: str = scheme_param[0]
        if not authorization or scheme.lower() != "bearer":
            raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        param: str = scheme_param[1]
        return param
    
class OAuth2AuthenticationRequestForm:
    """
    This is custom OAuth2AuthenticationRequest form
    Use it like:
        @app.post("/login")
        def login(form_data: OAuth2ClientCredentialsRequestForm = Depends()):
            data = form_data.parse()
            print(data.client_id)
            for scope in data.scopes:
                print(scope)
            return data
    It creates the following Form request parameters in your endpoint:
    grant_type: the OAuth2 spec says it is required and MUST be the fixed string "client_credentials".
        Nevertheless, this dependency class is permissive and allows not passing it.
    scope: Optional string. Several scopes (each one a string) separated by spaces. Currently unused.
    client_id: optional string. OAuth2 recommends sending the client_id and client_secret (if any)
        using HTTP Basic auth, as: client_id:client_secret
    client_secret: optional string. OAuth2 recommends sending the client_id and client_secret (if any)
        using HTTP Basic auth, as: client_id:client_secret
    """

    def __init__(
        self,
        grant_type: str = Form(regex="^(client_credentials|refresh_token|password|authorization_code)$"),
        scope: Optional[str] = Form(None),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
        username: Optional[str] = Form(None),
        password: Optional[str] = Form(None),
        state: Optional[str] = Form(None),
        code: Optional[str] = Form(None),
        refresh_token: Optional[str] = Form(None),
    ):
        self.grant_type = grant_type
        self.scopes = scope or None
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.state = state
        self.code = code
        self.refresh_token = refresh_token