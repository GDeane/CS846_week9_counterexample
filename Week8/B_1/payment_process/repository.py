from threading import Lock

_DATABASE = {}
_LOCK = Lock()


def save(payment):
    with _LOCK:
        _DATABASE[payment.id] = payment


def find_by_id(payment_id):
    return _DATABASE.get(payment_id)


def find_recent_by_user(user_id):
    return [
        p for p in _DATABASE.values()
        if p.user_id == user_id
    ]