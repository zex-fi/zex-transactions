from struct import calcsize, pack
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    UnexpectedCommandError,
)
from zex.transactions.update_withdraw_message import UpdateWithdrawMessage, Withdraw
from zex.utils.zex_types import ChainName


class TestWithdrawInstantiation:
    def test_given_status_r_when_creating_withdraw_then_status_is_r(self) -> None:
        withdraw = Withdraw(status="r", id=1, tx_hash=b"\xde\xad\xbe\xef")
        assert withdraw.status == "r"

    def test_given_status_s_when_creating_withdraw_then_status_is_s(self) -> None:
        withdraw = Withdraw(status="s", id=1, tx_hash=b"\xde\xad\xbe\xef")
        assert withdraw.status == "s"

    def test_given_invalid_status_when_creating_withdraw_then_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            Withdraw(status="x", id=1, tx_hash=b"\xde\xad\xbe\xef")  # pyright: ignore[reportArgumentType]

    def test_given_valid_fields_when_creating_withdraw_then_fields_are_stored(self) -> None:
        withdraw = Withdraw(status="r", id=42, tx_hash=b"\x00\x11\x22\x33\x44\x55\x66\x77")
        assert withdraw.id == 42
        assert withdraw.tx_hash == b"\x00\x11\x22\x33\x44\x55\x66\x77"


class TestWithdrawRoundTrip:
    def test_given_status_r_withdraw_when_calling_to_bytes_then_from_bytes_then_constructs_same_attributes(
        self,
    ) -> None:
        # Given
        original = Withdraw(status="r", id=100, tx_hash=b"\xde\xad\xbe\xef")

        # When
        data = original.to_bytes()
        recovered = Withdraw.from_bytes(data, len(original.tx_hash))

        # Then
        assert recovered.status == original.status
        assert recovered.id == original.id
        assert recovered.tx_hash == original.tx_hash

    def test_given_status_s_withdraw_when_calling_to_bytes_then_from_bytes_then_constructs_same_attributes(
        self,
    ) -> None:
        # Given
        original = Withdraw(status="s", id=999, tx_hash=b"\x01\x02\x03\x04")

        # When
        data = original.to_bytes()
        recovered = Withdraw.from_bytes(data, len(original.tx_hash))

        # Then
        assert recovered.status == original.status
        assert recovered.id == original.id
        assert recovered.tx_hash == original.tx_hash

    def test_given_large_withdraw_id_when_round_tripping_then_preserves_value(self) -> None:
        # Given
        original = Withdraw(status="r", id=2**63 - 1, tx_hash=b"\xff\xff\xff\xff")

        # When
        data = original.to_bytes()
        recovered = Withdraw.from_bytes(data, len(original.tx_hash))

        # Then
        assert recovered.id == original.id

    def test_given_to_bytes_output_when_checking_length_then_matches_struct_size(self) -> None:
        # Given: > 1s Q 4s = 1 + 8 + 4 = 13 bytes
        withdraw = Withdraw(status="r", id=1, tx_hash=b"\x00\x01\x02\x03")

        # When
        data = withdraw.to_bytes()

        # Then
        assert len(data) == 13


def _build_transaction_bytes(
    version: int = 1,
    command: bytes = b"u",
    chain: ChainName = ChainName.Ethereum,
    withdraws: list[Withdraw] | None = None,
    frost_sig: bytes = b"\x01" * 65,
    ecdsa_sig: bytes = b"\x02" * 65,
) -> bytes:
    """Build a complete UpdateWithdrawMessage byte payload from its components."""
    if withdraws is None:
        withdraws = [Withdraw(status="r", id=1, tx_hash=b"\xde\xad\xbe\xef")]
    tx_hash_length = len(withdraws[0].tx_hash)
    header = pack(
        UpdateWithdrawMessage.get_header_format(),
        version,
        int.from_bytes(command),
        chain.abbreviation.encode("utf-8"),
        tx_hash_length,
        len(withdraws),
    )
    body = b"".join(w.to_bytes() for w in withdraws)
    sig = pack(UpdateWithdrawMessage.get_signature_format(), frost_sig, ecdsa_sig)
    return header + body + sig


class TestUpdateWithdrawMessageFromBytes:
    FROST_SIG = b"\x01" * 65
    ECDSA_SIG = b"\x02" * 65

    def test_given_bytes_shorter_than_header_length_when_calling_from_bytes_then_raises_header_format_error(
        self,
    ) -> None:
        with pytest.raises(HeaderFormatError):
            UpdateWithdrawMessage.from_bytes(
                b"\x00" * (UpdateWithdrawMessage.HEADER_LENGTH - 1)
            )

    def test_given_empty_bytes_when_calling_from_bytes_then_raises_header_format_error(
        self,
    ) -> None:
        with pytest.raises(HeaderFormatError):
            UpdateWithdrawMessage.from_bytes(b"")

    def test_given_wrong_command_when_calling_from_bytes_then_raises_unexpected_command_error(
        self,
    ) -> None:
        # command = b"x", not the expected b"u" for UPDATE_WITHDRAW
        data = _build_transaction_bytes(command=b"x")
        with pytest.raises(UnexpectedCommandError):
            UpdateWithdrawMessage.from_bytes(data)

    def test_given_zero_withdraws_count_when_calling_from_bytes_then_raises_message_format_error(
        self,
    ) -> None:
        tx_hash_length = 4
        header = pack(
            UpdateWithdrawMessage.get_header_format(),
            1,
            int.from_bytes(b"u"),
            ChainName.Ethereum.abbreviation.encode("utf-8"),
            tx_hash_length,
            0,  # withdraws_count = 0
        )
        body_size = calcsize(UpdateWithdrawMessage.get_body_format(tx_hash_length))
        sig = pack(UpdateWithdrawMessage.get_signature_format(), self.FROST_SIG, self.ECDSA_SIG)
        data = header + b"\x00" * body_size + sig
        with pytest.raises(MessageFormatError, match="Invalid withdraw count"):
            UpdateWithdrawMessage.from_bytes(data)

    def test_given_body_too_short_when_calling_from_bytes_then_raises_message_format_error(
        self,
    ) -> None:
        tx_hash_length = 4
        header = pack(
            UpdateWithdrawMessage.get_header_format(),
            1,
            int.from_bytes(b"u"),
            ChainName.Ethereum.abbreviation.encode("utf-8"),
            tx_hash_length,
            1,  # claims 1 withdraw, but body will be empty
        )
        sig = pack(UpdateWithdrawMessage.get_signature_format(), self.FROST_SIG, self.ECDSA_SIG)
        data = header + sig  # no body
        with pytest.raises(MessageFormatError, match="Transaction body is too short"):
            UpdateWithdrawMessage.from_bytes(data)

    def test_given_valid_single_withdraw_when_calling_from_bytes_then_returns_correct_version(
        self,
    ) -> None:
        data = _build_transaction_bytes(version=3, frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert msg.version == 3

    def test_given_valid_single_withdraw_when_calling_from_bytes_then_returns_correct_withdraw_fields(
        self,
    ) -> None:
        withdraw = Withdraw(status="s", id=42, tx_hash=b"\xca\xfe\xba\xbe")
        data = _build_transaction_bytes(
            withdraws=[withdraw], frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG
        )
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert len(msg.withdraws) == 1
        assert msg.withdraws[0].status == "s"
        assert msg.withdraws[0].id == 42
        assert msg.withdraws[0].tx_hash == b"\xca\xfe\xba\xbe"

    def test_given_multiple_withdraws_when_calling_from_bytes_then_returns_all_withdraws(
        self,
    ) -> None:
        withdraws = [
            Withdraw(status="r", id=1, tx_hash=b"\x00\x01\x02\x03"),
            Withdraw(status="s", id=2, tx_hash=b"\x04\x05\x06\x07"),
            Withdraw(status="r", id=3, tx_hash=b"\x08\x09\x0a\x0b"),
        ]
        data = _build_transaction_bytes(
            withdraws=withdraws, frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG
        )
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert len(msg.withdraws) == 3
        for original, recovered in zip(withdraws, msg.withdraws):
            assert recovered.status == original.status
            assert recovered.id == original.id
            assert recovered.tx_hash == original.tx_hash

    def test_given_valid_bytes_when_calling_from_bytes_then_signatures_are_stored(
        self,
    ) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert msg.frost_signature == self.FROST_SIG
        assert msg.ecdsa_signature == self.ECDSA_SIG

    def test_given_valid_bytes_when_calling_from_bytes_then_transaction_bytes_is_stored(
        self,
    ) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert msg._transaction_bytes == data


def _build_message(
    version: int = 1,
    chain: ChainName = ChainName.Ethereum,
    withdraws: list[Withdraw] | None = None,
    frost_sig: bytes = b"\x01" * 65,
    ecdsa_sig: bytes = b"\x02" * 65,
) -> UpdateWithdrawMessage:
    if withdraws is None:
        withdraws = [Withdraw(status="r", id=1, tx_hash=b"\xde\xad\xbe\xef")]
    return UpdateWithdrawMessage(
        version=version,
        chain=chain,
        transaction_hash_length=len(withdraws[0].tx_hash),
        withdraws=withdraws,
        frost_signature=frost_sig,
        ecdsa_signature=ecdsa_sig,
    )


class TestUpdateWithdrawMessageInit:
    def test_given_frost_signature_with_wrong_length_when_creating_then_raises_value_error(
        self,
    ) -> None:
        with pytest.raises(ValueError, match="frost signature"):
            UpdateWithdrawMessage(
                version=1,
                chain=ChainName.Ethereum,
                transaction_hash_length=4,
                withdraws=[Withdraw(status="r", id=1, tx_hash=b"\x00" * 4)],
                frost_signature=b"\x00" * 64,  # wrong: should be 65
            )

    def test_given_ecdsa_signature_with_wrong_length_when_creating_then_raises_value_error(
        self,
    ) -> None:
        with pytest.raises(ValueError, match="ecdsa signature"):
            UpdateWithdrawMessage(
                version=1,
                chain=ChainName.Ethereum,
                transaction_hash_length=4,
                withdraws=[Withdraw(status="r", id=1, tx_hash=b"\x00" * 4)],
                ecdsa_signature=b"\x00" * 66,  # wrong: should be 65
            )

    def test_given_none_signatures_when_creating_then_attributes_are_none(self) -> None:
        msg = UpdateWithdrawMessage(
            version=1,
            chain=ChainName.Ethereum,
            transaction_hash_length=4,
            withdraws=[Withdraw(status="r", id=1, tx_hash=b"\x00" * 4)],
        )
        assert msg.frost_signature is None
        assert msg.ecdsa_signature is None

    def test_given_valid_signatures_when_creating_then_stored_correctly(self) -> None:
        frost = b"\xaa" * 65
        ecdsa = b"\xbb" * 65
        msg = UpdateWithdrawMessage(
            version=7,
            chain=ChainName.Ethereum,
            transaction_hash_length=4,
            withdraws=[Withdraw(status="s", id=99, tx_hash=b"\x00" * 4)],
            frost_signature=frost,
            ecdsa_signature=ecdsa,
        )
        assert msg.version == 7
        assert msg.frost_signature == frost
        assert msg.ecdsa_signature == ecdsa
        assert msg._transaction_bytes is None


class TestUpdateWithdrawMessageFormatMethods:
    def test_get_header_format_calcsize_matches_header_length(self) -> None:
        assert calcsize(UpdateWithdrawMessage.get_header_format()) == UpdateWithdrawMessage.HEADER_LENGTH

    def test_get_body_format_calcsize_matches_withdraw_to_bytes_length(self) -> None:
        tx_hash_length = 4
        withdraw = Withdraw(status="r", id=1, tx_hash=b"\x00" * tx_hash_length)
        assert calcsize(UpdateWithdrawMessage.get_body_format(tx_hash_length)) == len(withdraw.to_bytes())

    def test_get_signature_format_calcsize_matches_signature_length(self) -> None:
        assert calcsize(UpdateWithdrawMessage.get_signature_format()) == UpdateWithdrawMessage.SIGNATURE_LENGTH

    def test_get_message_format_calcsize_matches_header_plus_body(self) -> None:
        tx_hash_length = 8
        expected = UpdateWithdrawMessage.HEADER_LENGTH + calcsize(
            UpdateWithdrawMessage.get_body_format(tx_hash_length)
        )
        assert calcsize(UpdateWithdrawMessage.get_message_format(tx_hash_length)) == expected

    def test_get_format_calcsize_matches_full_message_size(self) -> None:
        tx_hash_length = 4
        expected = (
            UpdateWithdrawMessage.HEADER_LENGTH
            + calcsize(UpdateWithdrawMessage.get_body_format(tx_hash_length))
            + UpdateWithdrawMessage.SIGNATURE_LENGTH
        )
        assert calcsize(UpdateWithdrawMessage.get_format(tx_hash_length)) == expected


class TestUpdateWithdrawMessageStr:
    def test_str_contains_version(self) -> None:
        msg = _build_message(version=42)
        assert "42" in str(msg)

    def test_str_contains_transaction_hash_length(self) -> None:
        withdraw = Withdraw(status="r", id=1, tx_hash=b"\x00" * 8)
        msg = _build_message(withdraws=[withdraw])
        assert "transaction_hash_length: 8" in str(msg)


class TestUpdateWithdrawMessageToBytes:
    FROST_SIG = b"\x01" * 65
    ECDSA_SIG = b"\x02" * 65

    def test_given_cached_transaction_bytes_when_calling_to_bytes_then_returns_cached(
        self,
    ) -> None:
        # Simulate a message parsed from bytes — _transaction_bytes is already set.
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert msg.to_bytes() is msg._transaction_bytes

    def test_given_message_parsed_from_bytes_when_calling_to_bytes_then_returns_original_bytes(
        self,
    ) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert msg.to_bytes() == data


class TestUpdateWithdrawMessageRoundTrip:
    """Round-trip consistency: to_bytes ↔ from_bytes.

    Two directions are tested separately because from_bytes caches _transaction_bytes,
    which makes to_bytes return the original buffer directly. The more meaningful path
    starts from a freshly constructed message (no cache) so that to_bytes actually
    serialises the fields.
    """

    FROST_SIG = b"\x01" * 65
    ECDSA_SIG = b"\x02" * 65

    def test_given_message_constructed_directly_when_calling_to_bytes_then_from_bytes_then_fields_match(
        self,
    ) -> None:
        # Given – message built via constructor, so _transaction_bytes is None
        original = _build_message(
            version=2,
            withdraws=[
                Withdraw(status="r", id=77, tx_hash=b"\xde\xad\xbe\xef"),
            ],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        assert original._transaction_bytes is None  # no cache yet

        # When
        serialised = original.to_bytes()
        recovered = UpdateWithdrawMessage.from_bytes(serialised)

        # Then
        assert recovered.version == original.version
        assert recovered.transaction_hash_length == original.transaction_hash_length
        assert len(recovered.withdraws) == len(original.withdraws)
        assert recovered.withdraws[0].status == original.withdraws[0].status
        assert recovered.withdraws[0].id == original.withdraws[0].id
        assert recovered.withdraws[0].tx_hash == original.withdraws[0].tx_hash
        assert recovered.frost_signature == original.frost_signature
        assert recovered.ecdsa_signature == original.ecdsa_signature

    def test_given_message_constructed_directly_when_calling_to_bytes_then_from_bytes_then_to_bytes_then_bytes_are_equal(
        self,
    ) -> None:
        # Given – no cache; to_bytes must serialise from fields
        original = _build_message(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        assert original._transaction_bytes is None

        # When
        first_bytes = original.to_bytes()
        # from_bytes sets _transaction_bytes on the recovered message
        recovered = UpdateWithdrawMessage.from_bytes(first_bytes)
        second_bytes = recovered.to_bytes()  # returns cached value

        # Then
        assert first_bytes == second_bytes

    def test_given_bytes_parsed_via_from_bytes_when_calling_to_bytes_then_from_bytes_then_fields_match(
        self,
    ) -> None:
        # Given – parse first so _transaction_bytes is cached
        data = _build_transaction_bytes(
            version=5,
            withdraws=[Withdraw(status="s", id=123, tx_hash=b"\xca\xfe\xba\xbe")],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        first = UpdateWithdrawMessage.from_bytes(data)
        assert first._transaction_bytes is not None  # cache is set

        # When – to_bytes returns the cache, then parse again
        recovered = UpdateWithdrawMessage.from_bytes(first.to_bytes())

        # Then
        assert recovered.version == first.version
        assert recovered.transaction_hash_length == first.transaction_hash_length
        assert recovered.withdraws[0].status == first.withdraws[0].status
        assert recovered.withdraws[0].id == first.withdraws[0].id
        assert recovered.withdraws[0].tx_hash == first.withdraws[0].tx_hash
        assert recovered.frost_signature == first.frost_signature
        assert recovered.ecdsa_signature == first.ecdsa_signature

    def test_given_bytes_parsed_via_from_bytes_and_clear_cache_when_calling_to_bytes_then_from_bytes_then_fields_match(
        self,
    ) -> None:
        # Given
        data = _build_transaction_bytes(
            version=5,
            withdraws=[Withdraw(status="s", id=123, tx_hash=b"\xca\xfe\xba\xbe")],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        first = UpdateWithdrawMessage.from_bytes(data)

        first._transaction_bytes = None

        # When
        recovered = UpdateWithdrawMessage.from_bytes(first.to_bytes())

        # Then
        assert recovered.version == first.version
        assert recovered.transaction_hash_length == first.transaction_hash_length
        assert recovered.withdraws[0].status == first.withdraws[0].status
        assert recovered.withdraws[0].id == first.withdraws[0].id
        assert recovered.withdraws[0].tx_hash == first.withdraws[0].tx_hash
        assert recovered.frost_signature == first.frost_signature
        assert recovered.ecdsa_signature == first.ecdsa_signature


class TestUpdateWithdrawMessageCreateMessage:
    FROST_SIG = b"\x01" * 65
    ECDSA_SIG = b"\x02" * 65

    def test_given_single_withdraw_when_calling_create_message_then_length_matches_header_plus_body(
        self,
    ) -> None:
        withdraw = Withdraw(status="r", id=1, tx_hash=b"\xde\xad\xbe\xef")
        msg = _build_message(withdraws=[withdraw], frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        expected_length = (
            UpdateWithdrawMessage.HEADER_LENGTH
            + calcsize(UpdateWithdrawMessage.get_body_format(len(withdraw.tx_hash)))
        )
        assert len(msg.create_message()) == expected_length

    def test_given_multiple_withdraws_when_calling_create_message_then_length_includes_all_bodies(
        self,
    ) -> None:
        withdraws = [
            Withdraw(status="r", id=i, tx_hash=b"\x00" * 4) for i in range(3)
        ]
        msg = _build_message(withdraws=withdraws, frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        expected_length = UpdateWithdrawMessage.HEADER_LENGTH + 3 * calcsize(
            UpdateWithdrawMessage.get_body_format(4)
        )
        assert len(msg.create_message()) == expected_length


class TestUpdateWithdrawMessageVerifyFrostSignature:
    FROST_SIG = b"\xaa" * 65
    ECDSA_SIG = b"\xbb" * 65

    def test_given_curve_returns_true_when_verifying_frost_then_returns_true(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch("zex.transactions.update_withdraw_message.curve") as mock_curve:
            mock_curve.single_verify.return_value = True
            assert msg.verify_frost_signature("some_frost_public_key") is True

    def test_given_curve_returns_false_when_verifying_frost_then_returns_false(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch("zex.transactions.update_withdraw_message.curve") as mock_curve:
            mock_curve.single_verify.return_value = False
            assert msg.verify_frost_signature("some_frost_public_key") is False

    def test_given_valid_call_when_verifying_frost_then_calls_single_verify_with_correct_args(
        self,
    ) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        expected_message = data[: -UpdateWithdrawMessage.SIGNATURE_LENGTH]
        with patch("zex.transactions.update_withdraw_message.curve") as mock_curve:
            mock_curve.single_verify.return_value = True
            msg.verify_frost_signature("my_frost_key")
            mock_curve.single_verify.assert_called_once_with(
                self.FROST_SIG.hex(), expected_message, "my_frost_key"
            )


class TestUpdateWithdrawMessageVerifyEcdsaSignature:
    FROST_SIG = b"\xaa" * 65
    ECDSA_SIG = b"\xbb" * 65

    def test_given_recovered_address_matches_when_verifying_ecdsa_then_returns_true(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch("zex.transactions.update_withdraw_message.Web3") as mock_web3, patch(
            "zex.transactions.update_withdraw_message.encode_defunct"
        ):
            mock_web3.eth.account.recover_message.return_value = "0xShieldAddress"
            assert msg.verify_ecdsa_signature("0xShieldAddress") is True

    def test_given_recovered_address_does_not_match_when_verifying_ecdsa_then_returns_false(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch("zex.transactions.update_withdraw_message.Web3") as mock_web3, patch(
            "zex.transactions.update_withdraw_message.encode_defunct"
        ):
            mock_web3.eth.account.recover_message.return_value = "0xDifferentAddress"
            assert msg.verify_ecdsa_signature("0xShieldAddress") is False

    def test_given_valid_call_when_verifying_ecdsa_then_calls_recover_message_with_correct_args(
        self,
    ) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        expected_message = data[: -UpdateWithdrawMessage.SIGNATURE_LENGTH]
        with patch("zex.transactions.update_withdraw_message.Web3") as mock_web3, patch(
            "zex.transactions.update_withdraw_message.encode_defunct"
        ) as mock_encode_defunct:
            mock_web3.eth.account.recover_message.return_value = "0xShieldAddress"
            msg.verify_ecdsa_signature("0xShieldAddress")
            mock_encode_defunct.assert_called_once_with(expected_message)
            mock_web3.eth.account.recover_message.assert_called_once_with(
                mock_encode_defunct.return_value, signature=self.ECDSA_SIG
            )


class TestUpdateWithdrawMessageVerifySignature:
    FROST_SIG = b"\xcc" * 65
    ECDSA_SIG = b"\xdd" * 65

    def test_given_both_signatures_valid_when_verifying_then_returns_true(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch.object(msg, "verify_frost_signature", return_value=True), patch.object(
            msg, "verify_ecdsa_signature", return_value=True
        ):
            assert msg.verify_signature("frost_key", "shield_address") is True

    def test_given_frost_signature_invalid_when_verifying_then_returns_false(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch.object(msg, "verify_frost_signature", return_value=False), patch.object(
            msg, "verify_ecdsa_signature", return_value=True
        ):
            assert msg.verify_signature("frost_key", "shield_address") is False

    def test_given_ecdsa_signature_invalid_when_verifying_then_returns_false(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch.object(msg, "verify_frost_signature", return_value=True), patch.object(
            msg, "verify_ecdsa_signature", return_value=False
        ):
            assert msg.verify_signature("frost_key", "shield_address") is False
