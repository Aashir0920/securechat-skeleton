import json

def encode_message(action: str, payload: dict) -> str:
    return json.dumps({"action": action, "payload": payload})

def decode_message(msg: str) -> dict:
    return json.loads(msg)

