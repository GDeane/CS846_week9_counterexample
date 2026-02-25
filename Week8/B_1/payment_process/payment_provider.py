import random
import time
from exceptions import ProviderError


def charge(user_id, amount):
    # Simulate delay
    time.sleep(random.uniform(0, 0.2))

    # Simulate occasional failure
    if random.random() < 0.1:
        raise ProviderError("External provider failure")

    return {
        "external_id": str(random.randint(10000, 99999)),
        "status": "charged"
    }