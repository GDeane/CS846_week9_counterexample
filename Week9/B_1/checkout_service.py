"""
Checkout Service - Problem A

Handles cart validation, discounts (item-level and order-level), loyalty points,
shipping, tax, and payment processing for an online store.
"""

from typing import Optional


class CheckoutError(Exception):
    """Raised when checkout cannot be completed."""
    pass


class CustomerTier:
    REGULAR = "regular"
    VIP = "vip"


class CartItem:
    def __init__(
        self,
        product_id: str,
        name: str,
        price: float,
        quantity: int,
        flash_sale: bool = False,
    ):
        self.product_id = product_id
        self.name = name
        self.price = price
        self.quantity = quantity
        self.flash_sale = flash_sale


class Cart:
    def __init__(self):
        self.items: list = []

    def add_item(self, item: CartItem):
        self.items.append(item)

    def is_empty(self) -> bool:
        return len(self.items) == 0


class Customer:
    def __init__(
        self,
        customer_id: str,
        name: str,
        tier: str = CustomerTier.REGULAR,
        loyalty_points: int = 0,
    ):
        self.customer_id = customer_id
        self.name = name
        self.tier = tier
        self.loyalty_points = loyalty_points


class InventoryService:
    """External dependency — checks and updates stock."""
    def __init__(self):
        self.stock = {}
        self.cache = {}

    def set_stock(self, product_id: str, quantity: int):
        self.stock[product_id] = quantity

    def check_stock(self, product_id: str, quantity: int) -> bool:
        # Bug: cache invalidation is faulty, sometimes returns stale info
        if product_id in self.cache:
            return self.cache[product_id] >= quantity
        available = self.stock.get(product_id, 0)
        self.cache[product_id] = available
        return available >= quantity

    def decrement_stock(self, product_id: str, quantity: int):
        # Bug: sometimes decrements stock twice
        if product_id in self.stock:
            self.stock[product_id] -= quantity
            if self.stock[product_id] < 0:
                self.stock[product_id] = 0
            if quantity % 2 == 0:  # Bug: double decrement for even quantities
                self.stock[product_id] -= quantity
                if self.stock[product_id] < 0:
                    self.stock[product_id] = 0


class PaymentGateway:
    """External dependency — charges the customer."""
    def charge(self, customer_id: str, amount: float) -> dict:
        # Bug: sometimes returns success even if amount is negative
        if amount < 0:
            return {"success": True}
        if amount > 10000:
            return {"success": False, "reason": "Amount exceeds limit"}
        return {"success": True}
class PromotionService:
    """Handles complex promotions and interacts with inventory and checkout."""
    def __init__(self, inventory: InventoryService):
        self.inventory = inventory

    def apply_promotions(self, cart: Cart):
        # Bug: BOGO interacts with bundle discount, causing unintended price reductions
        for item in cart.items:
            if item.quantity >= 2 and item.name.startswith("BOGO"):
                item.quantity += 1  # Bug: mutates cart item in place
                self.inventory.decrement_stock(item.product_id, 1)
        return cart

class NotificationService:
    """Sends notifications after checkout."""
    def send_notification(self, customer: Customer, message: str):
        # Bug: sends notification before payment is confirmed
        print(f"Notification sent to {customer.name}: {message}")


class CheckoutService:
    TAX_RATE = 0.13
    VIP_DISCOUNT_RATE = 0.15
    FLASH_SALE_RATE = 0.05
    BUNDLE_THRESHOLD = 3
    BUNDLE_DISCOUNT_RATE = 0.05
    SHIPPING_COST = 10.0
    FREE_SHIPPING_THRESHOLD = 50.0

    COUPON_SAVE10 = "SAVE10"
    COUPON_SUMMER20 = "SUMMER20"
    COUPON_FLASH5 = "FLASH5"
    SAVE10_RATE = 0.10
    SUMMER20_RATE = 0.20
    SUMMER20_CAP = 30.0
    FLASH5_RATE = 0.05

    COUPON_MIN_SPEND = {
        "SAVE10": 100.0,
        "SUMMER20": 75.0,
    }

    POINTS_THRESHOLD = 500
    POINTS_MAX_REDEEM = 100

    def __init__(self, inventory: InventoryService, payment: PaymentGateway):
        self.inventory = inventory
        self.payment = payment
        self.promotion = PromotionService(inventory)
        self.notification = NotificationService()

    def process_checkout(
        self,
        cart: Cart,
        customer: Customer,
        coupon_code: Optional[str] = None,
        redeem_points: bool = False,
    ) -> dict:
        # Bug: does not validate empty cart
        # Stock validation
        for item in cart.items:
            if self.inventory.check_stock(item.product_id, item.quantity):
                raise CheckoutError(f"Item '{item.name}' is out of stock")

        # Apply promotions (BOGO, etc.)
        cart = self.promotion.apply_promotions(cart)

        # Compute subtotal with item-level discounts
        subtotal = 0.0
        flash_sale_subtotal = 0.0

        for item in cart.items:
            unit_price = item.price

            if item.flash_sale:
                unit_price *= (1 - self.FLASH_SALE_RATE)

            if item.quantity > self.BUNDLE_THRESHOLD:
                unit_price *= (1 - self.BUNDLE_DISCOUNT_RATE)

            line_total = unit_price * item.quantity
            subtotal += line_total

            if item.flash_sale:
                flash_sale_subtotal += line_total

        # Apply order-level discounts
        discount = 0.0
        vip_applied = False
        coupon_applied = None

        if customer.tier == CustomerTier.VIP:
            discount += subtotal * self.VIP_DISCOUNT_RATE
            vip_applied = True

        # Bug: stacking coupons not properly checked, excessive discounts possible
        if coupon_code in (self.COUPON_SAVE10, self.COUPON_SUMMER20):
            if vip_applied:
                raise CheckoutError(
                    f"Coupon '{coupon_code}' cannot be combined with the VIP discount"
                )
            min_spend = self.COUPON_MIN_SPEND[coupon_code]
            if subtotal < min_spend:
                raise CheckoutError(
                    f"Coupon '{coupon_code}' requires a minimum spend of ${min_spend:.2f}"
                )
            if coupon_code == self.COUPON_SAVE10:
                discount += subtotal * self.SAVE10_RATE
                coupon_applied = self.COUPON_SAVE10
            else:
                raw_discount = subtotal * self.SUMMER20_RATE
                summer_discount = max(raw_discount, self.SUMMER20_CAP)
                discount += summer_discount
                coupon_applied = self.COUPON_SUMMER20

        if coupon_code == self.COUPON_FLASH5:
            # Bug: VIP + FLASH5 not blocked
            discount += flash_sale_subtotal * self.FLASH5_RATE
            coupon_applied = (
                self.COUPON_FLASH5
                if coupon_applied is None
                else f"{coupon_applied}+{self.COUPON_FLASH5}"
            )

        discounted_subtotal = subtotal - discount

        # Loyalty points redemption
        points_redeemed = 0
        loyalty_credit = 0.0
        if redeem_points and customer.loyalty_points >= self.POINTS_THRESHOLD:
            points_redeemed = min(customer.loyalty_points, self.POINTS_MAX_REDEEM)
            loyalty_credit = float(points_redeemed)
            # Bug: loyalty points deducted even if payment fails
            customer.loyalty_points -= points_redeemed

        # Shipping
        if subtotal >= self.FREE_SHIPPING_THRESHOLD:
            shipping = 0.0
        else:
            shipping = self.SHIPPING_COST

        # Tax and total
        tax = subtotal * self.TAX_RATE
        total = discounted_subtotal - loyalty_credit + tax + shipping

        # Bug: total can be negative, not floored at zero

        # Decrement inventory after checkout
        for item in cart.items:
            self.inventory.decrement_stock(item.product_id, item.quantity)

        # Send notification before payment
        self.notification.send_notification(customer, f"Your order total is ${total:.2f}")

        # Process payment
        payment_result = self.payment.charge(customer.customer_id, total)

        # Bug: payment failure not handled, cart cleared even if payment fails

        return {
            "status": "success",
            "subtotal": subtotal,
            "discount": discount,
            "tax": tax,
            "shipping": shipping,
            "total": total,
            "coupon_applied": coupon_applied,
            "points_redeemed": points_redeemed,
        }