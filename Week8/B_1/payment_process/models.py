import uuid
from datetime import datetime


class Payment:
    def __init__(self, user_id, amount, currency):
        self.id = str(uuid.uuid4())
        self.user_id = user_id
        self.amount = amount
        self.currency = currency
        self.status = "pending"
        self.created_at = datetime.utcnow()