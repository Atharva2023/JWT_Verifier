
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import jwt

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-ozye7o1m.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE A2okOHspNjgA+2rTLbeUY
cxiP/hG8C6Sb9iwg3y1LAA4HCnpITcBWCSelvbYGuc3EbNy4xFyF5Cbj5DHJMID
EkryOqyd2qjIIIB0UBj8S63uGcnRpOBh9NFatFNwheKuzsPuVNldU6A9CtncXpXc
WyJjG2axVfmq7i6SUkR1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zcLR6BcmNN0/WVfJ4xyCLSf0BCOgdTgw6PdaChd1lgVDetJZVEgC5tkyvXsfi
SI6iyYrbKR0NEBSqq4XkadjEsCs4F1RncsS4Llgnl7GkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


class VerifyRequest(BaseModel):
    token: str


@app.post("/verify")
async def verify_token(body: VerifyRequest):
    try:
        claims = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "sub"],
            },
        )

        result = {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }
        return result

    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401,
            detail={"valid": False},
        )
