from payment_service import process_payment
from exceptions import PaymentError


def handle_request(payload):
    try:
        return process_payment(
            payload.get("user_id"),
            payload.get("amount"),
            payload.get("currency"),
        )
    except PaymentError as e:
        return {"error": str(e)}