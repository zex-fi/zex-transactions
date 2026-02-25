from decimal import Decimal

from pydantic import BaseModel

from zex.transactions.order_message import OrderMessage
from zex.utils.numbers import to_scientific
from zex.utils.zex_types import SignatureType, TransactionType


class BuyMessage(OrderMessage):
    TRANSACTION_TYPE = TransactionType.BUY


class BuySchema(BaseModel):
    sig_type: SignatureType
    base_token: str
    quote_token: str
    amount: str
    price: str
    t: int
    nonce: int
    user_id: int
    signature: str

    def to_message(self) -> BuyMessage:
        amount_mantissa, amount_exponent = to_scientific(Decimal(self.amount))
        price_mantissa, price_exponent = to_scientific(Decimal(self.price))
        return BuyMessage(
            version=1,
            signature_type=self.sig_type,
            base_token=self.base_token,
            quote_token=self.quote_token,
            amount_mantissa=amount_mantissa,
            amount_exponent=amount_exponent,
            price_mantissa=price_mantissa,
            price_exponent=price_exponent,
            time=self.t,
            nonce=self.nonce,
            user_id=self.user_id,
            signature_hex=self.signature,
        )
