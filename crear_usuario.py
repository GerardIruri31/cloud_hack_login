
import json
import os
from datetime import datetime
import hashlib

import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["USERS_TABLE"])


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body") or "{}")

        role = body.get("role")
        uuid = body.get("uuid")
        password = body.get("password")

        if not role or not uuid or not password:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "error": "Missing required fields: role, uuid, password"
                })
            }

        password_hash = hash_password(password)

        item = {
            "Role": role,
            "UUID": uuid,
            "UserId": body.get("userId"),
            "FullName": body.get("fullName"),
            "Email": body.get("email"),
            "Area": body.get("area"),
            "CommunityCode": body.get("communityCode"),
            "Status": body.get("status", "ACTIVE"),
            "CreatedAt": datetime.utcnow().isoformat(),
            "ToList": body.get("toList", []),
            "PasswordHash": password_hash,
        }

        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(#r) AND attribute_not_exists(#u)",
            ExpressionAttributeNames={
                "#r": "Role",
                "#u": "UUID"
            }
        )

        return {
            "statusCode": 201,
            "body": json.dumps({
                "message": "Usuario creado correctamente",
                "role": role,
                "uuid": uuid
            })
        }

    except Exception as e:
        print("Exception:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }

