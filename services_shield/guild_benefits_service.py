"""
Aither Shield - Guild Benefits Service

Manages tier-based benefits for Can I Be Guild members.
Integrates with vesting system for progressive discounts.
"""

from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
import uuid


class GuildTier(Enum):
    """Guild membership tiers based on vesting progress."""
    FREE = "free"
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    PLATINUM = "platinum"
    VESTED = "vested"


class BenefitType(Enum):
    """Types of benefits available."""
    DISCOUNT = "discount"
    FEATURE_UNLOCK = "feature_unlock"
    PRIORITY_ACCESS = "priority_access"
    BONUS_TOKENS = "bonus_tokens"
    COMMISSION_BOOST = "commission_boost"
    EXCLUSIVE_CONTENT = "exclusive_content"


@dataclass
class GuildMember:
    """Guild member profile."""
    id: str
    shield_user_id: str
    gigbee_id: Optional[str]
    tier: GuildTier
    vesting_percent: float
    joined_at: datetime
    tier_upgraded_at: datetime
    total_referrals: int = 0
    active_referrals: int = 0
    lifetime_earnings: Decimal = Decimal("0")
    monthly_earnings: Decimal = Decimal("0")
    benefits_used: Dict[str, int] = field(default_factory=dict)


@dataclass
class Benefit:
    """Benefit definition."""
    id: str
    name: str
    description: str
    benefit_type: BenefitType
    tier_required: GuildTier
    value: Any
    is_stackable: bool = False
    usage_limit: Optional[int] = None
    valid_until: Optional[datetime] = None


@dataclass
class BenefitUsage:
    """Record of benefit usage."""
    id: str
    member_id: str
    benefit_id: str
    used_at: datetime
    context: Dict[str, Any] = field(default_factory=dict)


class GuildBenefitsService:
    """
    Service for managing Guild member benefits.

    Benefits include:
    - Tier-based subscription discounts
    - Feature unlocks
    - Priority support access
    - Bonus token rewards
    - Commission rate boosts
    """

    # Tier thresholds based on vesting progress
    TIER_THRESHOLDS = {
        GuildTier.FREE: 0.0,
        GuildTier.BRONZE: 0.25,
        GuildTier.SILVER: 0.50,
        GuildTier.GOLD: 0.75,
        GuildTier.PLATINUM: 0.90,
        GuildTier.VESTED: 1.0,
    }

    # Discount rates by tier
    TIER_DISCOUNTS = {
        GuildTier.FREE: Decimal("0.00"),
        GuildTier.BRONZE: Decimal("0.05"),
        GuildTier.SILVER: Decimal("0.10"),
        GuildTier.GOLD: Decimal("0.15"),
        GuildTier.PLATINUM: Decimal("0.18"),
        GuildTier.VESTED: Decimal("0.20"),
    }

    # Commission boost by tier
    COMMISSION_BOOSTS = {
        GuildTier.FREE: Decimal("0.00"),
        GuildTier.BRONZE: Decimal("0.00"),
        GuildTier.SILVER: Decimal("0.05"),
        GuildTier.GOLD: Decimal("0.10"),
        GuildTier.PLATINUM: Decimal("0.15"),
        GuildTier.VESTED: Decimal("0.20"),
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._members: Dict[str, GuildMember] = {}
        self._benefits: Dict[str, Benefit] = {}
        self._usage_log: List[BenefitUsage] = []

        # Initialize default benefits
        self._initialize_benefits()

    def _initialize_benefits(self):
        """Set up default guild benefits."""
        benefits = [
            # Discount benefits
            Benefit(
                id="discount_bronze",
                name="Bronze Member Discount",
                description="5% off all Shield subscriptions",
                benefit_type=BenefitType.DISCOUNT,
                tier_required=GuildTier.BRONZE,
                value={"percent": 0.05},
            ),
            Benefit(
                id="discount_silver",
                name="Silver Member Discount",
                description="10% off all Shield subscriptions",
                benefit_type=BenefitType.DISCOUNT,
                tier_required=GuildTier.SILVER,
                value={"percent": 0.10},
            ),
            Benefit(
                id="discount_gold",
                name="Gold Member Discount",
                description="15% off all Shield subscriptions",
                benefit_type=BenefitType.DISCOUNT,
                tier_required=GuildTier.GOLD,
                value={"percent": 0.15},
            ),
            Benefit(
                id="discount_platinum",
                name="Platinum Member Discount",
                description="18% off all Shield subscriptions",
                benefit_type=BenefitType.DISCOUNT,
                tier_required=GuildTier.PLATINUM,
                value={"percent": 0.18},
            ),
            Benefit(
                id="discount_vested",
                name="Vested Member Discount",
                description="20% off all Shield subscriptions",
                benefit_type=BenefitType.DISCOUNT,
                tier_required=GuildTier.VESTED,
                value={"percent": 0.20},
            ),

            # Feature unlocks
            Benefit(
                id="priority_support_gold",
                name="Priority Support",
                description="24-hour response guarantee",
                benefit_type=BenefitType.PRIORITY_ACCESS,
                tier_required=GuildTier.GOLD,
                value={"response_hours": 24},
            ),
            Benefit(
                id="priority_support_platinum",
                name="VIP Support",
                description="4-hour response guarantee with dedicated agent",
                benefit_type=BenefitType.PRIORITY_ACCESS,
                tier_required=GuildTier.PLATINUM,
                value={"response_hours": 4, "dedicated_agent": True},
            ),

            # Bonus tokens
            Benefit(
                id="monthly_bee_silver",
                name="Monthly $BEE Bonus",
                description="10 $BEE tokens monthly",
                benefit_type=BenefitType.BONUS_TOKENS,
                tier_required=GuildTier.SILVER,
                value={"amount": 10, "token": "bee", "frequency": "monthly"},
            ),
            Benefit(
                id="monthly_bee_gold",
                name="Monthly $BEE Bonus",
                description="25 $BEE tokens monthly",
                benefit_type=BenefitType.BONUS_TOKENS,
                tier_required=GuildTier.GOLD,
                value={"amount": 25, "token": "bee", "frequency": "monthly"},
            ),
            Benefit(
                id="monthly_bee_platinum",
                name="Monthly $BEE Bonus",
                description="50 $BEE tokens monthly",
                benefit_type=BenefitType.BONUS_TOKENS,
                tier_required=GuildTier.PLATINUM,
                value={"amount": 50, "token": "bee", "frequency": "monthly"},
            ),

            # Commission boosts
            Benefit(
                id="commission_boost_silver",
                name="Commission Boost",
                description="+5% referral commission",
                benefit_type=BenefitType.COMMISSION_BOOST,
                tier_required=GuildTier.SILVER,
                value={"boost_percent": 0.05},
            ),
            Benefit(
                id="commission_boost_gold",
                name="Commission Boost",
                description="+10% referral commission",
                benefit_type=BenefitType.COMMISSION_BOOST,
                tier_required=GuildTier.GOLD,
                value={"boost_percent": 0.10},
            ),
            Benefit(
                id="commission_boost_platinum",
                name="Commission Boost",
                description="+15% referral commission",
                benefit_type=BenefitType.COMMISSION_BOOST,
                tier_required=GuildTier.PLATINUM,
                value={"boost_percent": 0.15},
            ),
            Benefit(
                id="commission_boost_vested",
                name="Elite Commission Boost",
                description="+20% referral commission",
                benefit_type=BenefitType.COMMISSION_BOOST,
                tier_required=GuildTier.VESTED,
                value={"boost_percent": 0.20},
            ),

            # Exclusive content
            Benefit(
                id="beta_access_gold",
                name="Beta Feature Access",
                description="Early access to new Shield features",
                benefit_type=BenefitType.EXCLUSIVE_CONTENT,
                tier_required=GuildTier.GOLD,
                value={"access_type": "beta"},
            ),
            Benefit(
                id="exclusive_webinars",
                name="Exclusive Security Webinars",
                description="Monthly security training webinars",
                benefit_type=BenefitType.EXCLUSIVE_CONTENT,
                tier_required=GuildTier.SILVER,
                value={"content_type": "webinar", "frequency": "monthly"},
            ),
        ]

        for benefit in benefits:
            self._benefits[benefit.id] = benefit

    def register_member(
        self,
        shield_user_id: str,
        gigbee_id: Optional[str] = None,
        vesting_percent: float = 0.0,
    ) -> Dict[str, Any]:
        """Register a new guild member."""
        tier = self._calculate_tier(vesting_percent)

        member = GuildMember(
            id=str(uuid.uuid4()),
            shield_user_id=shield_user_id,
            gigbee_id=gigbee_id,
            tier=tier,
            vesting_percent=vesting_percent,
            joined_at=datetime.now(),
            tier_upgraded_at=datetime.now(),
        )
        self._members[member.id] = member

        return {
            "success": True,
            "member_id": member.id,
            "tier": tier.value,
            "benefits": self.get_member_benefits(member.id),
        }

    def get_member(self, member_id: str) -> Optional[Dict[str, Any]]:
        """Get member details."""
        member = self._members.get(member_id)
        if not member:
            return None

        return {
            "id": member.id,
            "shield_user_id": member.shield_user_id,
            "gigbee_id": member.gigbee_id,
            "tier": member.tier.value,
            "vesting_percent": member.vesting_percent,
            "joined_at": member.joined_at.isoformat(),
            "total_referrals": member.total_referrals,
            "active_referrals": member.active_referrals,
            "lifetime_earnings": float(member.lifetime_earnings),
            "monthly_earnings": float(member.monthly_earnings),
        }

    def get_member_by_shield_user(self, shield_user_id: str) -> Optional[GuildMember]:
        """Find member by Shield user ID."""
        for member in self._members.values():
            if member.shield_user_id == shield_user_id:
                return member
        return None

    def update_vesting(
        self,
        member_id: str,
        new_vesting_percent: float,
    ) -> Dict[str, Any]:
        """Update member's vesting progress and tier."""
        member = self._members.get(member_id)
        if not member:
            return {"success": False, "error": "Member not found"}

        old_tier = member.tier
        member.vesting_percent = new_vesting_percent
        new_tier = self._calculate_tier(new_vesting_percent)

        tier_upgraded = new_tier.value != old_tier.value
        if tier_upgraded:
            member.tier = new_tier
            member.tier_upgraded_at = datetime.now()

        return {
            "success": True,
            "vesting_percent": new_vesting_percent,
            "old_tier": old_tier.value,
            "new_tier": new_tier.value,
            "tier_upgraded": tier_upgraded,
            "new_benefits": self.get_member_benefits(member_id) if tier_upgraded else None,
        }

    def get_member_benefits(self, member_id: str) -> List[Dict[str, Any]]:
        """Get all benefits available to member."""
        member = self._members.get(member_id)
        if not member:
            return []

        available_benefits = []
        tier_order = list(GuildTier)
        member_tier_index = tier_order.index(member.tier)

        for benefit in self._benefits.values():
            required_tier_index = tier_order.index(benefit.tier_required)
            if member_tier_index >= required_tier_index:
                available_benefits.append({
                    "id": benefit.id,
                    "name": benefit.name,
                    "description": benefit.description,
                    "type": benefit.benefit_type.value,
                    "tier_required": benefit.tier_required.value,
                    "value": benefit.value,
                })

        return available_benefits

    def get_discount_for_member(self, member_id: str) -> Dict[str, Any]:
        """Get applicable discount for member."""
        member = self._members.get(member_id)
        if not member:
            return {"discount_percent": 0, "tier": "free"}

        discount = self.TIER_DISCOUNTS.get(member.tier, Decimal("0"))

        return {
            "discount_percent": float(discount),
            "tier": member.tier.value,
            "next_tier": self._get_next_tier(member.tier),
            "vesting_to_next_tier": self._get_vesting_to_next_tier(member.vesting_percent),
        }

    def get_commission_boost(self, member_id: str) -> Dict[str, Any]:
        """Get commission boost for member."""
        member = self._members.get(member_id)
        if not member:
            return {"boost_percent": 0, "tier": "free"}

        boost = self.COMMISSION_BOOSTS.get(member.tier, Decimal("0"))

        return {
            "boost_percent": float(boost),
            "tier": member.tier.value,
            "base_commission": 0.15,
            "boosted_commission": 0.15 * (1 + float(boost)),
        }

    def apply_discount(
        self,
        member_id: str,
        base_price: float,
    ) -> Dict[str, Any]:
        """Apply guild discount to price."""
        member = self._members.get(member_id)
        if not member:
            return {
                "base_price": base_price,
                "discount_percent": 0,
                "discount_amount": 0,
                "final_price": base_price,
            }

        discount_percent = self.TIER_DISCOUNTS.get(member.tier, Decimal("0"))
        discount_amount = Decimal(str(base_price)) * discount_percent
        final_price = Decimal(str(base_price)) - discount_amount

        # Log benefit usage
        usage = BenefitUsage(
            id=str(uuid.uuid4()),
            member_id=member_id,
            benefit_id=f"discount_{member.tier.value}",
            used_at=datetime.now(),
            context={"base_price": base_price, "discount_applied": float(discount_amount)},
        )
        self._usage_log.append(usage)

        return {
            "base_price": base_price,
            "discount_percent": float(discount_percent),
            "discount_amount": float(discount_amount),
            "final_price": float(final_price),
            "tier": member.tier.value,
        }

    def claim_monthly_bonus(self, member_id: str) -> Dict[str, Any]:
        """Claim monthly token bonus."""
        member = self._members.get(member_id)
        if not member:
            return {"success": False, "error": "Member not found"}

        # Find applicable bonus benefit
        bonus_benefit = None
        for benefit in self._benefits.values():
            if (benefit.benefit_type == BenefitType.BONUS_TOKENS and
                self._tier_qualifies(member.tier, benefit.tier_required)):
                bonus_benefit = benefit

        if not bonus_benefit:
            return {"success": False, "error": "No bonus benefit available for your tier"}

        # Check if already claimed this month
        current_month = datetime.now().strftime("%Y-%m")
        claim_key = f"bonus_{current_month}"

        if claim_key in member.benefits_used:
            return {
                "success": False,
                "error": "Monthly bonus already claimed",
                "next_claim_date": (datetime.now().replace(day=1) + timedelta(days=32)).replace(day=1).isoformat(),
            }

        # Mark as claimed
        member.benefits_used[claim_key] = 1

        # Log usage
        usage = BenefitUsage(
            id=str(uuid.uuid4()),
            member_id=member_id,
            benefit_id=bonus_benefit.id,
            used_at=datetime.now(),
            context={"month": current_month, "amount": bonus_benefit.value["amount"]},
        )
        self._usage_log.append(usage)

        return {
            "success": True,
            "tokens_claimed": bonus_benefit.value["amount"],
            "token_type": bonus_benefit.value["token"],
            "tier": member.tier.value,
        }

    def get_tier_progress(self, member_id: str) -> Dict[str, Any]:
        """Get member's tier progress and next milestone."""
        member = self._members.get(member_id)
        if not member:
            return {"error": "Member not found"}

        current_tier = member.tier
        next_tier = self._get_next_tier(current_tier)
        vesting_to_next = self._get_vesting_to_next_tier(member.vesting_percent)

        return {
            "current_tier": current_tier.value,
            "vesting_percent": member.vesting_percent,
            "next_tier": next_tier.value if next_tier else None,
            "vesting_needed_for_next": vesting_to_next,
            "progress_to_next": self._calculate_progress_to_next(member.vesting_percent),
            "tier_benefits": self._get_tier_benefits_summary(current_tier),
            "next_tier_benefits": self._get_tier_benefits_summary(next_tier) if next_tier else None,
        }

    def get_tier_comparison(self) -> List[Dict[str, Any]]:
        """Get comparison of all tiers and their benefits."""
        comparison = []
        for tier in GuildTier:
            comparison.append({
                "tier": tier.value,
                "min_vesting": self.TIER_THRESHOLDS[tier],
                "discount_percent": float(self.TIER_DISCOUNTS[tier]),
                "commission_boost": float(self.COMMISSION_BOOSTS[tier]),
                "benefits": self._get_tier_benefits_summary(tier),
            })
        return comparison

    def _calculate_tier(self, vesting_percent: float) -> GuildTier:
        """Calculate tier based on vesting progress."""
        for tier in reversed(list(GuildTier)):
            if vesting_percent >= self.TIER_THRESHOLDS[tier]:
                return tier
        return GuildTier.FREE

    def _tier_qualifies(self, member_tier: GuildTier, required_tier: GuildTier) -> bool:
        """Check if member tier qualifies for required tier."""
        tier_order = list(GuildTier)
        return tier_order.index(member_tier) >= tier_order.index(required_tier)

    def _get_next_tier(self, current_tier: GuildTier) -> Optional[GuildTier]:
        """Get next tier after current."""
        tier_order = list(GuildTier)
        current_index = tier_order.index(current_tier)
        if current_index < len(tier_order) - 1:
            return tier_order[current_index + 1]
        return None

    def _get_vesting_to_next_tier(self, current_vesting: float) -> Optional[float]:
        """Calculate vesting needed for next tier."""
        for tier in GuildTier:
            threshold = self.TIER_THRESHOLDS[tier]
            if threshold > current_vesting:
                return threshold - current_vesting
        return None

    def _calculate_progress_to_next(self, current_vesting: float) -> float:
        """Calculate progress percentage to next tier."""
        current_tier = self._calculate_tier(current_vesting)
        next_tier = self._get_next_tier(current_tier)

        if not next_tier:
            return 100.0

        current_threshold = self.TIER_THRESHOLDS[current_tier]
        next_threshold = self.TIER_THRESHOLDS[next_tier]
        range_size = next_threshold - current_threshold

        if range_size == 0:
            return 100.0

        progress = (current_vesting - current_threshold) / range_size
        return min(100.0, max(0.0, progress * 100))

    def _get_tier_benefits_summary(self, tier: GuildTier) -> Dict[str, Any]:
        """Get summary of benefits for a tier."""
        return {
            "discount": f"{float(self.TIER_DISCOUNTS[tier]) * 100:.0f}%",
            "commission_boost": f"+{float(self.COMMISSION_BOOSTS[tier]) * 100:.0f}%",
            "priority_support": tier in [GuildTier.GOLD, GuildTier.PLATINUM, GuildTier.VESTED],
            "beta_access": tier in [GuildTier.GOLD, GuildTier.PLATINUM, GuildTier.VESTED],
            "monthly_bonus": tier not in [GuildTier.FREE, GuildTier.BRONZE],
        }
