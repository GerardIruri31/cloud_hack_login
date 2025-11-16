
import json
import os
import hashlib
import uuid
from datetime import datetime, timedelta

import boto3
from boto3.dynamodb.conditions import Attr

dynamodb = boto3.resource("dynamodb")
users_table = dynamodb.Table(os.environ["USERS_TABLE"])
tokens_table = dynamodb.Table(os.environ["TOKENS_TABLE"])


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body") or "{}")

        user_id = body.get("userId")
        password = body.get("password")

        if not user_id or not password:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "error": "Missing required fields: userId, password"
                })
            }

        # Buscar usuario por UserId (SCAN para simplificar)
        resp = users_table.scan(
            FilterExpression=Attr("UserId").eq(user_id) & Attr("Status").eq("ACTIVE")
        )

        if not resp.get("Items"):
            return {
                "statusCode": 403,
                "body": json.dumps({"error": "Usuario no existe o inactivo"})
            }

        user = resp["Items"][0]

        password_hash = hash_password(password)

        if user.get("PasswordHash") != password_hash:
            return {
                "statusCode": 403,
                "body": json.dumps({"error": "Password incorrecto"})
            }

        # Generar token
        token = str(uuid.uuid4())
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=60)

        token_item = {
            "Token": token,
            "UserId": user_id,
            "Role": user["Role"],
            "UUID": user["UUID"],
            "CreatedAt": now.isoformat(),
            "ExpiresAt": expires_at.isoformat(),
        }

        tokens_table.put_item(Item=token_item)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "token": token,
                "expiresAt": expires_at.isoformat()
            })
        }

    except Exception as e:
        print("Exception:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
