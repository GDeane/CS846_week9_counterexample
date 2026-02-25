from payment_process.payment_service import process_payment


def test_success():
    result = process_payment("user_1", 10, "USD")
    assert result["status"] == "charged"