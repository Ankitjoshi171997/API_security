from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel, constr, Field
from jose import jwt, jwk
from jose.exceptions import JWTError, JWKError
import requests
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import logging
import os

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

app.add_middleware(SlowAPIMiddleware)

# OAuth2 scheme setup (adjust URLs as needed)
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=os.getenv("AUTH_URL", "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"),
    tokenUrl=os.getenv("TOKEN_URL", "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
    scopes={"api://your-api-client-id/access_as_user": "Access API as a user"}
)

# Azure AD details
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
API_AUDIENCE = os.getenv("API_AUDIENCE")  # usually the API's Application (client) ID or App URI

# Fetch JWKS keys for verifying tokens
def get_jwks():
    response = requests.get(JWKS_URL)
    response.raise_for_status()
    return response.json()

jwks = get_jwks()

def verify_token(token: str):
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing kid header")
        
        key = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Appropriate key not found")
        
        public_key = jwk.construct(key)
        message, encoded_signature = token.rsplit('.', 1)
        
        if not public_key.verify(message.encode("utf-8"), jwt.base64url_decode(encoded_signature.encode("utf-8"))):
            raise HTTPException(status_code=401, detail="Signature verification failed")
        
        payload = jwt.decode(token, public_key.to_pem().decode(), audience=API_AUDIENCE, algorithms=[key["alg"]])
        return payload
    
    except (JWTError, JWKError) as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

class SecureDataRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: str = Field(..., pattern=r'^\S+@\S+\.\S+$')
    comment: str = Field(None, max_length=500)

@app.get("/")
def root():
    return {"message": "API is up and running"}

@app.get("/secure-data")
@limiter.limit("5/minute")
async def secure_data(request: Request, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    roles = payload.get("roles", [])
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="User does not have required role")
    
    logger.info(f"User {payload.get('preferred_username')} accessed secure data")
    return {"message": "Secure data accessed!", "token_payload": payload}

@app.post("/submit-data")
@limiter.limit("10/minute")
async def submit_data(request: Request, data: SecureDataRequest, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    logger.info(f"User {payload.get('preferred_username')} submitted data: {data.dict()}")
    return {"message": "Data received successfully", "submitted_data": data.dict()}

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return HTTPException(status_code=429, detail="Rate limit exceeded")

# uvicorn main:app --reload

