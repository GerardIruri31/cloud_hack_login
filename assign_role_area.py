import json
import os
from datetime import datetime, timezone

import boto3

dynamodb = boto3.resource("dynamodb")
users_table = dynamodb.Table(os.environ["USERS_TABLE"])
tokens_table = dynamodb.Table(os.environ["TOKENS_TABLE"])


def parse_iso_to_utc(s: str):
    if s.endswith("Z"):
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    else:
        dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _get_authorization_token(headers: dict):
    if not headers:
        return None
    auth = (
        headers.get("Authorization")
        or headers.get("authorization")
        or headers.get("Bearer")
        or headers.get("bearer")
    )
    if not auth:
        return None

    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return auth


def _get_user_from_token(token: str):
    resp = tokens_table.get_item(Key={"Token": token})
    if "Item" not in resp:
        return None

    token_item = resp["Item"]
    expires_at_str = token_item.get("ExpiresAt")
    if not expires_at_str:
        return None

    expires_at = parse_iso_to_utc(expires_at_str)
    now = datetime.now(timezone.utc)
    if now > expires_at:
        return None

    role = token_item["Role"]
    uuid = token_item["UUID"]

    user_resp = users_table.get_item(Key={"Role": role, "UUID": uuid})
    if "Item" not in user_resp:
        return None

    return user_resp["Item"]


def lambda_handler(event, context):
    try:
        # 1. Validar token y que sea AUTHORITY
        headers = event.get("headers") or {}
        token = _get_authorization_token(headers)

        if not token:
            return {
                "statusCode": 401,
                "body": json.dumps({"error": "Missing or invalid Authorization header"})
            }

        auth_user = _get_user_from_token(token)
        if not auth_user:
            return {
                "statusCode": 403,
                "body": json.dumps({"error": "Token inválido o expirado"})
            }

        if auth_user.get("Role") != "AUTHORITY":
            return {
                "statusCode": 403,
                "body": json.dumps({"error": "Solo usuarios con rol AUTHORITY pueden asignar roles y áreas"})
            }

        # 2. Leer body
        body = json.loads(event.get("body") or "{}")

        current_role = body.get("currentRole")
        uuid = body.get("uuid")
        new_role = body.get("newRole")
        new_area = body.get("newArea")

        if not current_role or not uuid or not new_role or not new_area:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "error": "Missing required fields: currentRole, uuid, newRole, newArea"
                })
            }

        # 3. Traer usuario objetivo
        user_resp = users_table.get_item(Key={"Role": current_role, "UUID": uuid})
        if "Item" not in user_resp:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "Usuario objetivo no encontrado"})
            }

        target_user = user_resp["Item"]

        # 4. No permitir editar alumnos (COMMUNITY)
        if target_user.get("Role") == "COMMUNITY":
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "No se puede cambiar el rol de usuarios COMMUNITY (alumnos)"})
            }

        # 5. Si solo cambia el área (nuevo rol = mismo rol)
        if new_role == current_role:
            users_table.update_item(
                Key={"Role": current_role, "UUID": uuid},
                UpdateExpression="SET #a = :newArea",
                ExpressionAttributeNames={
                    "#a": "Area"
                },
                ExpressionAttributeValues={
                    ":newArea": new_area
                }
            )

            target_user["Area"] = new_area

            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Área actualizada correctamente",
                    "user": target_user
                })
            }

        # 6. Si cambia también el rol (cambia la PK)
        # Crear nuevo item con el nuevo rol y misma UUID
        new_item = dict(target_user)
        new_item["Role"] = new_role
        new_item["Area"] = new_area
        new_item["UpdatedAt"] = datetime.now(timezone.utc).isoformat()

        # Insertar nuevo
        users_table.put_item(Item=new_item)

        # Borrar el viejo
        users_table.delete_item(Key={"Role": current_role, "UUID": uuid})

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Rol y área actualizados correctamente",
                "user": new_item
            })
        }

    except Exception as e:
        print("Exception in assign_role_area:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
