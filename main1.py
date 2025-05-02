# app.py
from typing import Optional, List
from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, validator
from bson import ObjectId
from pymongo import MongoClient
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import bcrypt
from fastapi_jwt_auth import AuthJWT
from pymongo.errors import DuplicateKeyError
from bson.errors import InvalidId
import os
from fastapi.middleware.cors import CORSMiddleware



# App initialization
app = FastAPI()

# MongoDB connection
client = MongoClient("mongodb+srv://dbuser:Ashar123@cluster0.1cquqzc.mongodb.net/")
db = client["lms"]

# Create indexes on startup

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Settings
class Settings(BaseModel):
    authjwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
    authjwt_access_token_expires: timedelta = timedelta(seconds=3600)
    authjwt_refresh_token_expires: timedelta = timedelta(seconds=86400)

@AuthJWT.load_config
def get_config():
    return Settings()

# Pydantic models
class LeadIn(BaseModel):
    aadhaar_no: str = Field(..., description="12-digit Aadhaar number")
    pan_no: str = Field(..., description="10-character PAN number")
    last_name: str = Field(..., description="Last name of the lead")
    address: Optional[str] = Field(None, description="Address of the lead")
    email: EmailStr = Field(..., description="Email address")
    contact: str = Field(..., description="Contact phone number")

    @validator('aadhaar_no')
    def validate_aadhaar(cls, v):
        if not v.isdigit() or len(v) != 12:
            raise ValueError('Aadhaar must be exactly 12 digits')
        return v

    @validator('pan_no')
    def validate_pan(cls, v):
        if len(v) != 10 or not v[:5].isalpha() or not v[5:9].isdigit() or not v[9].isalpha():
            raise ValueError('PAN must be 10 characters: 5 letters, 4 digits, 1 letter')
        return v.upper()

class LeadOut(LeadIn):
    id: str = Field(..., alias="_id")

class GenericResponse(BaseModel):
    success: bool
    message: str
    data: Optional[object] = None
    errorMessage: Optional[str] = None

class SignupPayload(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    password: str
    assignedRole: Optional[List[str]] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(GenericResponse):
    access_token:str
    refresh_token:str

# Auth Service Implementation
class AuthServiceImpl:
    def validate_cred(self, body):
        user = db.users.find_one({"email": body["email"]})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "message": "Login failed",
                    "errorMessage": "Invalid email"
                }
            )
        if not bcrypt.checkpw(body["password"].encode('utf-8'), user["password"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "message": "Login failed",
                    "errorMessage": "Invalid password"
                }
            )
        return user

# Permission dependency
def PermissionRequired(permission: str):
    def dependency(Authorize: AuthJWT = Depends()):
        try:
            Authorize.jwt_required()
            user_id = Authorize.get_jwt_subject()
            user = db.users.find_one({"_id": ObjectId(user_id)})
            if not user or permission not in user.get("assignedRole", []):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "success": False,
                        "message": "Permission denied",
                        "errorMessage": "You don't have permission to access this resource"
                    }
                )
            return user
        except InvalidId:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": "Invalid user",
                    "errorMessage": "Invalid user ID"
                }
            )
    return Depends(dependency)

# Routes
lead_router = APIRouter(prefix="/core/api/leads", tags=["leads"])
auth_router = APIRouter(prefix="/core/api/auth", tags=["auth"])

@auth_router.post("/signup", response_model=GenericResponse)
async def signup(payload: SignupPayload, _ = PermissionRequired("USER:CREATE")):
    try:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(payload.password.encode('utf-8'), salt)
        user_data = {
            "firstName": payload.firstName,
            "lastName": payload.lastName,
            "email": payload.email,
            "password": hashed_password,
            "createdOn": datetime.now(),
            "updatedOn": datetime.now(),
            "status": "Active",
            "assignedRole": payload.assignedRole or []
        }
        result = db.users.insert_one(user_data)
        return GenericResponse(
            success=True,
            message="User created successfully",
            data={"id": str(result.inserted_id)}
        )
    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": "Signup failed",
                "errorMessage": "User already exists"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "Signup failed",
                "errorMessage": str(e)
            }
        )

@auth_router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, Authorize: AuthJWT = Depends()):
    try:
        auth_service = AuthServiceImpl()
        user = auth_service.validate_cred(request.dict())
        access_token = Authorize.create_access_token(subject=str(user["_id"]))
        refresh_token = Authorize.create_refresh_token(subject=str(user["_id"]))
        return LoginResponse(
            success=True,
            message="Login successful",
            access_token=access_token,
            refresh_token=refresh_token
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "Login failed",
                "errorMessage": str(e)
            }
        )

@auth_router.get("/refresh", response_model=LoginResponse)
async def refresh_token(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_refresh_token_required()
        current_user = Authorize.get_jwt_subject()
        new_access_token = Authorize.create_access_token(subject=current_user)
        return LoginResponse(
            success=True,
            message="Token refreshed",
            data={"access_token": new_access_token}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "message": "Refresh failed",
                "errorMessage": "Invalid refresh token"
            }
        )

# Ping endpoint
@app.get("/ping", response_model=GenericResponse)
async def ping():
    return GenericResponse(success=True, message="pong")
#
# # Lead routes
# @lead_router.post("/leads", response_model=GenericResponse, status_code=status.HTTP_201_CREATED)
# def create_lead(lead: LeadIn):
#     try:
#         if db.leads.find_one({"aadhaar_no": lead.aadhaar_no}):
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail={
#                     "success": False,
#                     "message": "Creation failed",
#                     "errorMessage": "Aadhaar number already exists"
#                 }
#             )
#         if db.leads.find_one({"pan_no": lead.pan_no}):
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail={
#                     "success": False,
#                     "message": "Creation failed",
#                     "errorMessage": "PAN number already exists"
#                 }
#             )
#         doc = lead.dict()
#         res = db.leads.insert_one(doc)
#         created = db.leads.find_one({"_id": res.inserted_id})
#         return GenericResponse(
#             success=True,
#             message="Lead created successfully",
#             data=str(created["_id"])
#         )
#     except HTTPException as e:
#         raise e
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail={
#                 "success": False,
#                 "message": "Creation failed",
#                 "errorMessage": str(e)
#             }
#         )

# Include other lead routes (GET, PUT, DELETE) similarly...
# ... (keep all previous imports and setup from your original code)

# Add these to the existing imports
from bson.errors import InvalidId


# Helper to format Mongo document (add this above the lead routes)
def format_lead(doc) -> LeadOut:
    doc['_id'] = str(doc['_id'])
    return LeadOut(**doc)


# Update existing lead routes with the new endpoints
@lead_router.get("/", response_model=GenericResponse)
def list_leads(limit: int = 100, skip: int = 0):
    try:
        cursor = db.leads.find().skip(skip).limit(limit)
        leads = [format_lead(doc).dict(by_alias=True) for doc in cursor]
        return GenericResponse(
            success=True,
            message="Leads retrieved successfully",
            data=leads
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "Retrieval failed",
                "errorMessage": str(e)
            }
        )


@lead_router.get("/{lead_id}", response_model=GenericResponse)
def get_lead(lead_id: str):
    try:
        oid = ObjectId(lead_id)
        doc = db.leads.find_one({"_id": oid})
        if not doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "message": "Retrieval failed",
                    "errorMessage": "Lead not found"
                }
            )
        lead_out = format_lead(doc)
        return GenericResponse(
            success=True,
            message="Lead retrieved successfully",
            data=lead_out.dict(by_alias=True)
        )
    except InvalidId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": "Invalid lead ID",
                "errorMessage": "Invalid lead ID format"
            }
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "Retrieval failed",
                "errorMessage": str(e)
            }
        )


@lead_router.put("/{lead_id}", response_model=GenericResponse)
def update_lead(lead_id: str, lead: LeadIn):
    try:
        oid = ObjectId(lead_id)
        update_data = lead.dict()

        # Check for existing Aadhaar/PAN in other documents
        existing_aadhaar = db.leads.find_one({
            "aadhaar_no": update_data["aadhaar_no"],
            "_id": {"$ne": oid}
        })
        if existing_aadhaar:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "message": "Update failed",
                    "errorMessage": "Aadhaar number already exists"
                }
            )

        existing_pan = db.leads.find_one({
            "pan_no": update_data["pan_no"],
            "_id": {"$ne": oid}
        })
        if existing_pan:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "message": "Update failed",
                    "errorMessage": "PAN number already exists"
                }
            )

        result = db.leads.update_one({"_id": oid}, {"$set": update_data})
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "message": "Update failed",
                    "errorMessage": "Lead not found"
                }
            )

        doc = db.leads.find_one({"_id": oid})
        lead_out = format_lead(doc)
        return GenericResponse(
            success=True,
            message="Lead updated successfully",
            data=lead_out.dict(by_alias=True))
    except InvalidId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": "Invalid lead ID",
                "errorMessage": "Invalid lead ID format"
            }
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "Update failed",
                "errorMessage": str(e)
            }
        )


@lead_router.delete("/{lead_id}", response_model=GenericResponse)
def delete_lead(lead_id: str):
    try:
        oid = ObjectId(lead_id)
        result = db.leads.delete_one({"_id": oid})
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "message": "Deletion failed",
                    "errorMessage": "Lead not found"
                }
            )
        return GenericResponse(
            success=True,
            message="Lead deleted successfully"
        )
    except InvalidId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": "Invalid lead ID",
                "errorMessage": "Invalid lead ID format"
            }
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "Deletion failed",
                "errorMessage": str(e)
            }
        )


# Update the existing create_lead endpoint to use format_lead
@lead_router.post("/", response_model=GenericResponse, status_code=status.HTTP_201_CREATED)
def create_lead(lead: LeadIn):
    try:
        if db.leads.find_one({"aadhaar_no": lead.aadhaar_no}):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "message": "Creation failed",
                    "errorMessage": "Aadhaar number already exists"
                }
            )
        if db.leads.find_one({"pan_no": lead.pan_no}):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "message": "Creation failed",
                    "errorMessage": "PAN number already exists"
                }
            )
        doc = lead.dict()
        res = db.leads.insert_one(doc)
        created = db.leads.find_one({"_id": res.inserted_id})
        lead_out = format_lead(created)
        return GenericResponse(
            success=True,
            message="Lead created successfully",
            data=lead_out.dict(by_alias=True)
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "Creation failed",
                "errorMessage": str(e)
            }
        )


app.include_router(lead_router)
app.include_router(auth_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)