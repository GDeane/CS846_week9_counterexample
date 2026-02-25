from api import handle_request


if __name__ == "__main__":
    payload = {
        "user_id": "user_1",
        "amount": 49.99,
        "currency": "USD"
    }

    print(handle_request(payload))