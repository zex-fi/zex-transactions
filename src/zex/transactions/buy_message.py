from decimal import Decimal

from pydantic import BaseModel

from zex.transactions.order_message import OrderMessage
from zex.transactions.utils import to_scientific
from zex.transactions.zex_types import TransactionType


class BuyMessage(OrderMessage):
    TRANSACTION_TYPE = TransactionType.BUY


class BuySchema(BaseModel):
    sig_type: int
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
            signature_type_value=self.sig_type,
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
