from zex.transactions import DepositMessage, Deposit
from zex.utils.zex_types import ChainName
from coincurve import PrivateKey
from frost_lib.curves import secp256k1 as curve
from eth_account import Account


def test_given_output_of_to_bytes_when_calling_from_bytes_then_construct_the_same_attributes() -> None:
    # Given
    original_deposit_message = DepositMessage(
        version=1,
        chain=ChainName.Ethereum,
        transaction_hash_length=0,
        token_contract_length=0,
        deposits=[
            Deposit(
                transaction_hash=b"",
                token_contract=b"",
                amount=10,
                decimal=18,
                time=1000,
                salt_length=1,
                vout=1,
                salt=1,
            ),
        ],
    )
    frost_keypair = curve.keypair_new()
    ecdsa_account = Account.create()
    original_deposit_message.sign(
        PrivateKey(),
        frost_keypair,
        ecdsa_account,
    )

    # When
    transaction_bytes = original_deposit_message.to_bytes()
    new_deposit_message = DepositMessage.from_bytes(transaction_bytes)

    # Then
    assert new_deposit_message.version == original_deposit_message.version
    assert new_deposit_message.chain == original_deposit_message.chain
    assert new_deposit_message.transaction_hash_length == original_deposit_message.transaction_hash_length
    assert new_deposit_message.token_contract_length == original_deposit_message.token_contract_length
    assert new_deposit_message.deposits == original_deposit_message.deposits
