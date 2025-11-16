import json
import os
import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["USERS_TABLE"])

def lambda_handler(event, context):
    try:
        # Obtener parámetros de ruta
        path_params = event.get("pathParameters") or {}
        role = path_params.get("role")
        uuid = path_params.get("uuid")

        if not role or not uuid:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "error": "Missing required path parameters: role, uuid"
                })
            }

        # Obtener usuario en DynamoDB
        resp = table.get_item(
            Key={
                "Role": role,
                "UUID": uuid
            }
        )

        if "Item" not in resp:
            return {
                "statusCode": 404,
                "body": json.dumps({
                    "error": "Usuario no encontrado"
                })
            }

        user = resp["Item"]

        # Remover el hash de contraseña por seguridad
        user.pop("PasswordHash", None)

        return {
            "statusCode": 200,
            "body": json.dumps(user)
        }

    except Exception as e:
        print("Exception:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
