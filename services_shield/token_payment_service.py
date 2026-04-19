"""
Aither Shield - Token Payment Service

Handles $GIG and $BEE token payments for Shield subscriptions.
Integrates with OROBOROS tokenomics.
"""

from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
import uuid


class PaymentMethod(Enum):
    """Supported payment methods."""
    FIAT_CARD = "fiat_card"
    FIAT_BANK = "fiat_bank"
    GIG_TOKEN = "gig_token"
    BEE_TOKEN = "bee_token"
    CRYPTO_ETH = "crypto_eth"
    CRYPTO_USDC = "crypto_usdc"


class PaymentStatus(Enum):
    """Payment transaction status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"


class TransactionType(Enum):
    """Transaction types."""
    SUBSCRIPTION = "subscription"
    RENEWAL = "renewal"
    UPGRADE = "upgrade"
    REFUND = "refund"
    TOKEN_PURCHASE = "token_purchase"
    COMMISSION_PAYOUT = "commission_payout"


@dataclass
class TokenWallet:
    """User token wallet."""
    user_id: str
    gig_balance: Decimal = Decimal("0")
    bee_balance: Decimal = Decimal("0")
    bee_vested: Decimal = Decimal("0")
    bee_unvested: Decimal = Decimal("0")
    pending_payouts: Decimal = Decimal("0")
    wallet_address: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class PaymentTransaction:
    """Payment transaction record."""
    id: str
    user_id: str
    transaction_type: TransactionType
    payment_method: PaymentMethod
    amount: Decimal
    currency: str
    token_amount: Optional[Decimal] = None
    token_type: Optional[str] = None
    status: PaymentStatus = PaymentStatus.PENDING
    subscription_id: Optional[str] = None
    referrer_id: Optional[str] = None
    commission_amount: Optional[Decimal] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


@dataclass
class SubscriptionPayment:
    """Subscription payment details."""
    id: str
    user_id: str
    plan_slug: str
    payment_method: PaymentMethod
    amount: Decimal
    currency: str
    billing_cycle: str  # 'monthly' or 'yearly'
    discount_applied: Decimal = Decimal("0")
    discount_reason: Optional[str] = None
    next_billing_date: datetime = field(default_factory=datetime.now)
    status: str = "active"
    created_at: datetime = field(default_factory=datetime.now)


class TokenPaymentService:
    """
    Token payment service for Aither Shield subscriptions.

    Handles:
    - $GIG token payments
    - $BEE token redemption
    - Fiat to token conversion
    - Subscription payments
    - Commission payouts
    """

    # OROBOROS constants
    REVENUE_SPLIT = {
        "buyback_pool": Decimal("0.60"),      # 60% buys $BEE
        "stability_reserve": Decimal("0.40"),  # 40% backs $GIG
    }
    HONEY_FEE = Decimal("0.025")  # 2.5% transaction fee
    SHIELD_COMMISSION_RATE = Decimal("0.15")  # 15% commission
    FIRST_YEAR_BONUS = Decimal("1.5")  # 1.5x first year

    # Token exchange rates (in production, fetch from oracle)
    TOKEN_RATES = {
        "gig_usd": Decimal("1.00"),  # $GIG is pegged to USD
        "bee_usd": Decimal("0.10"),  # $BEE initial rate
        "eth_usd": Decimal("3000.00"),
        "usdc_usd": Decimal("1.00"),
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._wallets: Dict[str, TokenWallet] = {}
        self._transactions: Dict[str, PaymentTransaction] = {}
        self._subscriptions: Dict[str, SubscriptionPayment] = {}

    def get_or_create_wallet(self, user_id: str) -> TokenWallet:
        """Get or create user token wallet."""
        if user_id not in self._wallets:
            self._wallets[user_id] = TokenWallet(user_id=user_id)
        return self._wallets[user_id]

    def get_wallet_balance(self, user_id: str) -> Dict[str, Any]:
        """Get user's token wallet balances."""
        wallet = self.get_or_create_wallet(user_id)
        return {
            "user_id": user_id,
            "gig_balance": float(wallet.gig_balance),
            "bee_balance": float(wallet.bee_balance),
            "bee_vested": float(wallet.bee_vested),
            "bee_unvested": float(wallet.bee_unvested),
            "pending_payouts": float(wallet.pending_payouts),
            "wallet_address": wallet.wallet_address,
            "total_value_usd": self._calculate_wallet_value(wallet),
        }

    def process_subscription_payment(
        self,
        user_id: str,
        plan_slug: str,
        amount: float,
        payment_method: str,
        billing_cycle: str = "yearly",
        referrer_id: Optional[str] = None,
        vesting_percent: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Process subscription payment.

        Supports token payments with vesting discounts.
        """
        payment_method_enum = PaymentMethod(payment_method)
        amount_decimal = Decimal(str(amount))

        # Calculate vesting discount
        discount_percent = self._calculate_vesting_discount(vesting_percent)
        discount_amount = amount_decimal * Decimal(str(discount_percent))
        final_amount = amount_decimal - discount_amount

        # For token payments, check balance
        if payment_method_enum == PaymentMethod.GIG_TOKEN:
            wallet = self.get_or_create_wallet(user_id)
            if wallet.gig_balance < final_amount:
                return {
                    "success": False,
                    "error": "Insufficient $GIG balance",
                    "required": float(final_amount),
                    "available": float(wallet.gig_balance),
                }
            # Deduct tokens
            wallet.gig_balance -= final_amount
            wallet.updated_at = datetime.now()

        elif payment_method_enum == PaymentMethod.BEE_TOKEN:
            wallet = self.get_or_create_wallet(user_id)
            # Convert USD to BEE
            bee_rate = self.TOKEN_RATES["bee_usd"]
            bee_required = final_amount / bee_rate

            if wallet.bee_vested < bee_required:
                return {
                    "success": False,
                    "error": "Insufficient vested $BEE balance",
                    "required": float(bee_required),
                    "available": float(wallet.bee_vested),
                }
            # Deduct tokens
            wallet.bee_balance -= bee_required
            wallet.bee_vested -= bee_required
            wallet.updated_at = datetime.now()

        # Create transaction
        transaction = PaymentTransaction(
            id=str(uuid.uuid4()),
            user_id=user_id,
            transaction_type=TransactionType.SUBSCRIPTION,
            payment_method=payment_method_enum,
            amount=final_amount,
            currency="USD",
            status=PaymentStatus.COMPLETED,
            subscription_id=None,
            referrer_id=referrer_id,
            metadata={
                "plan_slug": plan_slug,
                "billing_cycle": billing_cycle,
                "original_amount": float(amount),
                "discount_percent": discount_percent,
                "discount_amount": float(discount_amount),
                "vesting_percent": vesting_percent,
            },
            completed_at=datetime.now(),
        )

        # Calculate commission if referred
        commission_amount = None
        if referrer_id:
            commission_amount = self._calculate_commission(
                final_amount,
                is_first_year=True,
                referrer_tier="bronze",
            )
            transaction.commission_amount = commission_amount
            self._add_pending_commission(referrer_id, commission_amount)

        # Apply OROBOROS revenue split
        revenue_split = self._apply_revenue_split(final_amount)

        self._transactions[transaction.id] = transaction

        # Create subscription
        subscription = SubscriptionPayment(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_slug=plan_slug,
            payment_method=payment_method_enum,
            amount=final_amount,
            currency="USD",
            billing_cycle=billing_cycle,
            discount_applied=discount_amount,
            discount_reason=f"Vesting discount ({discount_percent*100:.0f}%)" if discount_amount > 0 else None,
            next_billing_date=datetime.now() + timedelta(
                days=365 if billing_cycle == "yearly" else 30
            ),
        )
        self._subscriptions[subscription.id] = subscription
        transaction.subscription_id = subscription.id

        return {
            "success": True,
            "transaction_id": transaction.id,
            "subscription_id": subscription.id,
            "amount_charged": float(final_amount),
            "discount_applied": float(discount_amount),
            "payment_method": payment_method,
            "commission_generated": float(commission_amount) if commission_amount else None,
            "revenue_split": {
                "buyback_pool": float(revenue_split["buyback_pool"]),
                "stability_reserve": float(revenue_split["stability_reserve"]),
            },
            "next_billing_date": subscription.next_billing_date.isoformat(),
        }

    def purchase_tokens(
        self,
        user_id: str,
        token_type: str,
        usd_amount: float,
        payment_method: str,
    ) -> Dict[str, Any]:
        """Purchase $GIG or $BEE tokens with fiat."""
        amount = Decimal(str(usd_amount))

        # Calculate token amount
        if token_type == "gig":
            token_amount = amount  # 1:1 for $GIG
        elif token_type == "bee":
            token_amount = amount / self.TOKEN_RATES["bee_usd"]
        else:
            return {"success": False, "error": "Invalid token type"}

        # Apply honey fee
        fee = token_amount * self.HONEY_FEE
        net_amount = token_amount - fee

        # Create transaction
        transaction = PaymentTransaction(
            id=str(uuid.uuid4()),
            user_id=user_id,
            transaction_type=TransactionType.TOKEN_PURCHASE,
            payment_method=PaymentMethod(payment_method),
            amount=amount,
            currency="USD",
            token_amount=net_amount,
            token_type=token_type,
            status=PaymentStatus.COMPLETED,
            metadata={"fee": float(fee), "rate": float(self.TOKEN_RATES.get(f"{token_type}_usd", 1))},
            completed_at=datetime.now(),
        )
        self._transactions[transaction.id] = transaction

        # Credit wallet
        wallet = self.get_or_create_wallet(user_id)
        if token_type == "gig":
            wallet.gig_balance += net_amount
        else:
            wallet.bee_balance += net_amount
            wallet.bee_unvested += net_amount  # Purchased tokens start unvested
        wallet.updated_at = datetime.now()

        return {
            "success": True,
            "transaction_id": transaction.id,
            "token_type": token_type,
            "tokens_purchased": float(net_amount),
            "fee_charged": float(fee),
            "usd_spent": float(amount),
            "new_balance": float(wallet.gig_balance if token_type == "gig" else wallet.bee_balance),
        }

    def process_commission_payout(
        self,
        user_id: str,
        payout_method: str = "gig_token",
    ) -> Dict[str, Any]:
        """Process referral commission payout."""
        wallet = self.get_or_create_wallet(user_id)

        if wallet.pending_payouts <= 0:
            return {"success": False, "error": "No pending payouts"}

        payout_amount = wallet.pending_payouts

        # Create transaction
        transaction = PaymentTransaction(
            id=str(uuid.uuid4()),
            user_id=user_id,
            transaction_type=TransactionType.COMMISSION_PAYOUT,
            payment_method=PaymentMethod(payout_method),
            amount=payout_amount,
            currency="USD",
            status=PaymentStatus.COMPLETED,
            metadata={"payout_method": payout_method},
            completed_at=datetime.now(),
        )
        self._transactions[transaction.id] = transaction

        # Credit wallet based on payout method
        if payout_method == "gig_token":
            wallet.gig_balance += payout_amount
        elif payout_method == "bee_token":
            bee_amount = payout_amount / self.TOKEN_RATES["bee_usd"]
            wallet.bee_balance += bee_amount
            wallet.bee_unvested += bee_amount

        wallet.pending_payouts = Decimal("0")
        wallet.updated_at = datetime.now()

        return {
            "success": True,
            "transaction_id": transaction.id,
            "payout_amount": float(payout_amount),
            "payout_method": payout_method,
        }

    def get_transaction_history(
        self,
        user_id: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Get user's transaction history."""
        transactions = [t for t in self._transactions.values() if t.user_id == user_id]
        transactions.sort(key=lambda x: x.created_at, reverse=True)

        return [{
            "id": t.id,
            "type": t.transaction_type.value,
            "payment_method": t.payment_method.value,
            "amount": float(t.amount),
            "currency": t.currency,
            "token_amount": float(t.token_amount) if t.token_amount else None,
            "token_type": t.token_type,
            "status": t.status.value,
            "created_at": t.created_at.isoformat(),
            "completed_at": t.completed_at.isoformat() if t.completed_at else None,
        } for t in transactions[:limit]]

    def get_subscription(self, subscription_id: str) -> Optional[Dict[str, Any]]:
        """Get subscription details."""
        sub = self._subscriptions.get(subscription_id)
        if not sub:
            return None

        return {
            "id": sub.id,
            "user_id": sub.user_id,
            "plan_slug": sub.plan_slug,
            "payment_method": sub.payment_method.value,
            "amount": float(sub.amount),
            "billing_cycle": sub.billing_cycle,
            "discount_applied": float(sub.discount_applied),
            "discount_reason": sub.discount_reason,
            "next_billing_date": sub.next_billing_date.isoformat(),
            "status": sub.status,
            "created_at": sub.created_at.isoformat(),
        }

    def calculate_price_with_discount(
        self,
        plan_slug: str,
        base_price: float,
        vesting_percent: float = 0.0,
        use_bee_payment: bool = False,
    ) -> Dict[str, Any]:
        """Calculate final price with all applicable discounts."""
        base = Decimal(str(base_price))

        # Vesting discount
        vesting_discount = self._calculate_vesting_discount(vesting_percent)
        vesting_savings = base * Decimal(str(vesting_discount))

        # BEE payment bonus (5% extra if paying with $BEE)
        bee_bonus = Decimal("0.05") if use_bee_payment else Decimal("0")
        bee_savings = base * bee_bonus

        total_discount = vesting_discount + float(bee_bonus)
        final_price = base - vesting_savings - bee_savings

        return {
            "base_price": float(base),
            "vesting_discount_percent": vesting_discount,
            "vesting_savings": float(vesting_savings),
            "bee_payment_bonus_percent": float(bee_bonus),
            "bee_payment_savings": float(bee_savings),
            "total_discount_percent": total_discount,
            "total_savings": float(vesting_savings + bee_savings),
            "final_price": float(final_price),
            "bee_tokens_required": float(final_price / self.TOKEN_RATES["bee_usd"]) if use_bee_payment else None,
        }

    def _calculate_vesting_discount(self, vesting_percent: float) -> float:
        """Calculate discount based on vesting progress."""
        if vesting_percent >= 1.0:
            return 0.20
        elif vesting_percent >= 0.75:
            return 0.15
        elif vesting_percent >= 0.50:
            return 0.10
        elif vesting_percent >= 0.25:
            return 0.05
        return 0.0

    def _calculate_commission(
        self,
        amount: Decimal,
        is_first_year: bool,
        referrer_tier: str,
    ) -> Decimal:
        """Calculate referral commission."""
        base_commission = amount * self.SHIELD_COMMISSION_RATE

        if is_first_year:
            base_commission *= self.FIRST_YEAR_BONUS

        # Tier bonuses
        tier_bonus = {
            "bronze": Decimal("0"),
            "silver": Decimal("0.05"),
            "gold": Decimal("0.10"),
            "platinum": Decimal("0.15"),
            "diamond": Decimal("0.20"),
        }.get(referrer_tier, Decimal("0"))

        return base_commission * (Decimal("1") + tier_bonus)

    def _add_pending_commission(self, referrer_id: str, amount: Decimal) -> None:
        """Add commission to referrer's pending payouts."""
        wallet = self.get_or_create_wallet(referrer_id)
        wallet.pending_payouts += amount
        wallet.updated_at = datetime.now()

    def _apply_revenue_split(self, amount: Decimal) -> Dict[str, Decimal]:
        """Apply OROBOROS revenue split."""
        return {
            "buyback_pool": amount * self.REVENUE_SPLIT["buyback_pool"],
            "stability_reserve": amount * self.REVENUE_SPLIT["stability_reserve"],
        }

    def _calculate_wallet_value(self, wallet: TokenWallet) -> float:
        """Calculate total wallet value in USD."""
        gig_value = wallet.gig_balance * self.TOKEN_RATES["gig_usd"]
        bee_value = wallet.bee_balance * self.TOKEN_RATES["bee_usd"]
        return float(gig_value + bee_value)
