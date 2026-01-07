import json


def handle(_item):
    return None


def dump_items(items):
    payload = json.dumps(items)
    for item in items:
        handle(item)
    return payload
