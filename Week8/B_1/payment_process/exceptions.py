class PaymentError(Exception):
    pass


class ValidationError(PaymentError):
    pass


class ProviderError(PaymentError):
    pass