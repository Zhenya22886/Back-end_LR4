from datetime import datetime, timezone
from decimal import Decimal

from flask import jsonify, request
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
)

from app import app, db
from app.models import User, Category, Record, Account

# Healthcheck 

@app.get("/healthcheck")
def healthcheck():
    return jsonify({
        "status": "ok",
        "date": datetime.now(timezone.utc).isoformat()
    }), 200

# Helpers

def error_response(message: str, status_code: int = 400):
    return jsonify({"error": message}), status_code


def user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "name": user.name,
    }


def category_to_dict(category: Category) -> dict:
    return {
        "id": category.id,
        "name": category.name,
    }


def record_to_dict(record: Record) -> dict:
    return {
        "id": record.id,
        "user_id": record.user_id,
        "category_id": record.category_id,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "amount": float(record.amount) if record.amount is not None else None,
    }


def account_to_dict(account: Account) -> dict:
    return {
        "id": account.id,
        "user_id": account.user_id,
        "balance": float(account.balance) if account.balance is not None else 0.0,
    }


# Authentication

@app.post("/user")
def register_user():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")
    name = data.get("name")

    if not username or not password or not name:
        return error_response(
            "Fields 'username', 'password' and 'name' are required"
        )

    if User.query.filter_by(username=username).first() is not None:
        return error_response("User with this username already exists", 400)

    user = User(
        username=username,
        password=pbkdf2_sha256.hash(password),
        name=name,
    )

    db.session.add(user)
    db.session.commit()

    return jsonify(user_to_dict(user)), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return error_response("Fields 'username' and 'password' are required")

    user = User.query.filter_by(username=username).first()

    if user and pbkdf2_sha256.verify(password, user.password):
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200

    return error_response("Invalid username or password", 401)

# USERS 

@app.get("/user/<int:user_id>")
@jwt_required()
def get_user(user_id: int):
    _current_user_id = get_jwt_identity()  

    user = User.query.get(user_id)
    if user is None:
        return error_response("User not found", 404)
    return jsonify(user_to_dict(user)), 200


@app.delete("/user/<int:user_id>")
@jwt_required()
def delete_user(user_id: int):
    _current_user_id = get_jwt_identity()

    user = User.query.get(user_id)
    if user is None:
        return error_response("User not found", 404)

    db.session.delete(user)
    db.session.commit()

    return jsonify({"status": "deleted"}), 200


@app.get("/users")
@jwt_required()
def list_users():
    _current_user_id = get_jwt_identity()

    all_users = User.query.order_by(User.id.asc()).all()
    return jsonify([user_to_dict(u) for u in all_users]), 200


# ACCOUNTS 

@app.get("/user/<int:user_id>/account")
@jwt_required()
def get_account(user_id: int):
    _current_user_id = get_jwt_identity()

    user = User.query.get(user_id)
    if user is None:
        return error_response("User not found", 404)

    account = user.account
    if account is None:
        account = Account(user_id=user.id, balance=Decimal("0"))
        db.session.add(account)
        db.session.commit()

    return jsonify(account_to_dict(account)), 200


@app.post("/user/<int:user_id>/account/deposit")
@jwt_required()
def deposit_to_account(user_id: int):
    _current_user_id = get_jwt_identity()

    user = User.query.get(user_id)
    if user is None:
        return error_response("User not found", 404)

    data = request.get_json(silent=True) or {}

    if "amount" not in data:
        return error_response("Field 'amount' is required")

    try:
        amount_value = float(data["amount"])
    except (TypeError, ValueError):
        return error_response("Field 'amount' must be a number")

    if amount_value <= 0:
        return error_response("Field 'amount' must be positive")

    amount_dec = Decimal(str(amount_value))

    account = user.account
    if account is None:
        account = Account(user_id=user.id, balance=Decimal("0"))
        db.session.add(account)

    account.balance = (account.balance or Decimal("0")) + amount_dec
    db.session.commit()

    return jsonify(account_to_dict(account)), 200

# CATEGORIES 

@app.get("/category")
@jwt_required()
def list_categories():
    _current_user_id = get_jwt_identity()

    categories = Category.query.order_by(Category.id.asc()).all()
    return jsonify([category_to_dict(c) for c in categories]), 200


@app.post("/category")
@jwt_required()
def create_category():
    _current_user_id = get_jwt_identity()

    data = request.get_json(silent=True) or {}

    name = data.get("name")
    if not name:
        return error_response("Field 'name' is required")

    category = Category(name=name)
    db.session.add(category)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return error_response("Category with this name already exists", 400)

    return jsonify(category_to_dict(category)), 201


@app.delete("/category")
@jwt_required()
def delete_category():
    _current_user_id = get_jwt_identity()

    category_id = request.args.get("id", type=int)
    if category_id is None:
        return error_response("Query parameter 'id' is required")

    category = Category.query.get(category_id)
    if category is None:
        return error_response("Category not found", 404)

    db.session.delete(category)
    db.session.commit()

    return jsonify({"status": "deleted"}), 200

# RECORDS 

@app.get("/record/<int:record_id>")
@jwt_required()
def get_record(record_id: int):
    _current_user_id = get_jwt_identity()

    record = Record.query.get(record_id)
    if record is None:
        return error_response("Record not found", 404)
    return jsonify(record_to_dict(record)), 200


@app.delete("/record/<int:record_id>")
@jwt_required()
def delete_record(record_id: int):
    _current_user_id = get_jwt_identity()

    record = Record.query.get(record_id)
    if record is None:
        return error_response("Record not found", 404)

    db.session.delete(record)
    db.session.commit()

    return jsonify({"status": "deleted"}), 200


@app.post("/record")
@jwt_required()
def create_record():
    _current_user_id = get_jwt_identity()

    data = request.get_json(silent=True) or {}

    required_fields = ["user_id", "category_id", "amount"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        return error_response(f"Missing fields: {', '.join(missing)}")

    user_id = data["user_id"]
    category_id = data["category_id"]

    user = User.query.get(user_id)
    if user is None:
        return error_response("User does not exist")

    category = Category.query.get(category_id)
    if category is None:
        return error_response("Category does not exist")

    try:
        amount_value = float(data["amount"])
    except (TypeError, ValueError):
        return error_response("Field 'amount' must be a number")

    if amount_value <= 0:
        return error_response("Field 'amount' must be positive")

    amount_dec = Decimal(str(amount_value))

    created_at_str = data.get("created_at")
    if created_at_str:
        try:
            created_at = datetime.fromisoformat(created_at_str)
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
        except ValueError:
            return error_response("Field 'created_at' must be valid ISO datetime")
    else:
        created_at = datetime.now(timezone.utc)

    account = user.account
    if account is None:
        account = Account(user_id=user.id, balance=Decimal("0"))
        db.session.add(account)
        db.session.flush()

    current_balance = account.balance or Decimal("0")

    if current_balance < amount_dec:
        return error_response("Insufficient funds on account", 400)

    account.balance = current_balance - amount_dec

    record = Record(
        user_id=user.id,
        category_id=category.id,
        created_at=created_at,
        amount=amount_dec,
    )

    db.session.add(record)
    db.session.commit()

    return jsonify(record_to_dict(record)), 201


@app.get("/record")
@jwt_required()
def list_records():
    _current_user_id = get_jwt_identity()

    user_id = request.args.get("user_id", type=int)
    category_id = request.args.get("category_id", type=int)

    if user_id is None and category_id is None:
        return error_response("At least one of 'user_id' or 'category_id' must be provided")

    query = Record.query

    if user_id is not None:
        query = query.filter(Record.user_id == user_id)
    if category_id is not None:
        query = query.filter(Record.category_id == category_id)

    records = query.order_by(Record.id.asc()).all()
    return jsonify([record_to_dict(r) for r in records]), 200
