from models import Payment
from repository import save, find_recent_by_user
from payment_provider import charge
from exceptions import ValidationError, ProviderError


SUPPORTED_CURRENCIES = {"USD", "EUR"}


def process_payment(user_id, amount, currency):
    # Basic validation
    if not user_id:
        raise ValidationError("User ID required")

    if amount <= 0:
        raise ValidationError("Amount must be positive")

    if currency not in SUPPORTED_CURRENCIES:
        raise ValidationError("Unsupported currency")

    # Naive duplicate protection (same amount within short window)
    recent = find_recent_by_user(user_id)
    for p in recent:
        if p.amount == amount and p.status == "charged":
            raise ValidationError("Duplicate payment detected")

    payment = Payment(user_id, amount, currency)

    try:
        provider_response = charge(user_id, amount)
        payment.status = provider_response["status"]
    except ProviderError:
        payment.status = "failed"
        save(payment)
        raise

    save(payment)

    return {
        "payment_id": payment.id,
        "status": payment.status
    }