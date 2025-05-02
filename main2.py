from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from bson.errors import InvalidId
from datetime import timedelta, datetime
import bcrypt
import os

app = Flask(__name__)
CORS(app)

# Config
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=3600)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(seconds=86400)

jwt = JWTManager(app)

# Mongo setup
client = MongoClient("mongodb+srv://dbuser:Ashar123@cluster0.1cquqzc.mongodb.net/")
db = client["lms"]

# Helpers
def format_lead(doc):
    doc["_id"] = str(doc["_id"])
    return doc

def validate_aadhaar(aadhaar):
    return aadhaar.isdigit() and len(aadhaar) == 12

def validate_pan(pan):
    return len(pan) == 10 and pan[:5].isalpha() and pan[5:9].isdigit() and pan[9].isalpha()

# Auth endpoints
@app.route("/core/api/auth/signup", methods=["POST"])
@jwt_required(optional=True)
def signup():
    try:
        data = request.json
        password_hash = bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt())
        user_data = {
            "firstName": data["firstName"],
            "lastName": data["lastName"],
            "email": data["email"],
            "password": password_hash,
            "createdOn": datetime.now(),
            "updatedOn": datetime.now(),
            "status": "Active",
            "assignedRole": data.get("assignedRole", [])
        }
        db.users.insert_one(user_data)
        return jsonify(success=True, message="User created successfully"), 201
    except DuplicateKeyError:
        return jsonify(success=False, message="Signup failed", errorMessage="User already exists"), 400
    except Exception as e:
        return jsonify(success=False, message="Signup failed", errorMessage=str(e)), 500

@app.route("/core/api/auth/login", methods=["POST"])
def login():
    try:
        data = request.json
        user = db.users.find_one({"email": data["email"]})
        if not user or not bcrypt.checkpw(data["password"].encode("utf-8"), user["password"]):
            return jsonify(success=False, message="Login failed", errorMessage="Invalid credentials"), 400

        user_id = str(user["_id"])
        access_token = create_access_token(identity=user_id)
        refresh_token = create_refresh_token(identity=user_id)
        return jsonify(success=True, message="Login successful", access_token=access_token, refresh_token=refresh_token)
    except Exception as e:
        return jsonify(success=False, message="Login failed", errorMessage=str(e)), 500

@app.route("/core/api/auth/refresh", methods=["GET"])
@jwt_required(refresh=True)
def refresh_token():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(success=True, message="Token refreshed", access_token=access_token)

# Lead routes
@app.route("/core/api/leads", methods=["POST"])
@jwt_required()
def create_lead():
    try:
        data = request.json
        if not validate_aadhaar(data["aadhaar_no"]):
            return jsonify(success=False, message="Creation failed", errorMessage="Invalid Aadhaar"), 400
        if not validate_pan(data["pan_no"]):
            return jsonify(success=False, message="Creation failed", errorMessage="Invalid PAN"), 400

        if db.leads.find_one({"aadhaar_no": data["aadhaar_no"]}) or db.leads.find_one({"pan_no": data["pan_no"]}):
            return jsonify(success=False, message="Creation failed", errorMessage="Duplicate Aadhaar or PAN"), 400

        result = db.leads.insert_one(data)
        created = db.leads.find_one({"_id": result.inserted_id})
        return jsonify(success=True, message="Lead created", data=format_lead(created)), 201
    except Exception as e:
        return jsonify(success=False, message="Creation failed", errorMessage=str(e)), 500

@app.route("/core/api/leads", methods=["GET"])
@jwt_required()
def list_leads():
    try:
        skip = int(request.args.get("skip", 0))
        limit = int(request.args.get("limit", 100))
        leads = db.leads.find().skip(skip).limit(limit)
        return jsonify(success=True, message="Leads retrieved", data=[format_lead(lead) for lead in leads])
    except Exception as e:
        return jsonify(success=False, message="Retrieval failed", errorMessage=str(e)), 500

@app.route("/core/api/leads/<lead_id>", methods=["GET"])
@jwt_required()
def get_lead(lead_id):
    try:
        lead = db.leads.find_one({"_id": ObjectId(lead_id)})
        if not lead:
            return jsonify(success=False, message="Lead not found", errorMessage="Lead not found"), 404
        return jsonify(success=True, message="Lead retrieved", data=format_lead(lead))
    except InvalidId:
        return jsonify(success=False, message="Invalid lead ID", errorMessage="Invalid lead ID format"), 400

@app.route("/core/api/leads/<lead_id>", methods=["PUT"])
@jwt_required()
def update_lead(lead_id):
    try:
        data = request.json
        oid = ObjectId(lead_id)

        if db.leads.find_one({"aadhaar_no": data["aadhaar_no"], "_id": {"$ne": oid}}):
            return jsonify(success=False, message="Update failed", errorMessage="Duplicate Aadhaar"), 400
        if db.leads.find_one({"pan_no": data["pan_no"], "_id": {"$ne": oid}}):
            return jsonify(success=False, message="Update failed", errorMessage="Duplicate PAN"), 400

        result = db.leads.update_one({"_id": oid}, {"$set": data})
        if result.matched_count == 0:
            return jsonify(success=False, message="Update failed", errorMessage="Lead not found"), 404

        updated = db.leads.find_one({"_id": oid})
        return jsonify(success=True, message="Lead updated", data=format_lead(updated))
    except InvalidId:
        return jsonify(success=False, message="Invalid lead ID", errorMessage="Invalid lead ID format"), 400

@app.route("/core/api/leads/<lead_id>", methods=["DELETE"])
@jwt_required()
def delete_lead(lead_id):
    try:
        result = db.leads.delete_one({"_id": ObjectId(lead_id)})
        if result.deleted_count == 0:
            return jsonify(success=False, message="Deletion failed", errorMessage="Lead not found"), 404
        return jsonify(success=True, message="Lead deleted")
    except InvalidId:
        return jsonify(success=False, message="Invalid lead ID", errorMessage="Invalid lead ID format"), 400

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify(success=True, message="pong")

if __name__ == "__main__":
    app.run(debug=True, port=8000)
