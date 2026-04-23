from struct import calcsize, pack
from unittest.mock import patch

import pytest

from zex.transactions.exceptions import (
    HeaderFormatError,
    MessageFormatError,
    UnexpectedCommandError,
)
from zex.transactions.update_withdraw_message import (
    UpdatedWithdrawal,
    UpdateWithdrawMessage,
    UpdateWithdrawMessageStatus,
)
from zex.utils.zex_types import ChainName



class TestUpdateWithdrawRoundTrip:
    def test_given_zero_hash_length_when_round_tripping_then_constructs_same_attributes(
        self,
    ) -> None:
        # Given
        original = UpdatedWithdrawal(id=100, tx_hash=b"")

        # When
        data = original.to_bytes()
        recovered, _ = UpdatedWithdrawal.from_bytes(data, 0)

        # Then
        assert recovered.id == original.id
        assert recovered.tx_hash == b""

    def test_given_nonzero_hash_when_round_tripping_then_constructs_same_attributes(
        self,
    ) -> None:
        # Given
        original = UpdatedWithdrawal(id=999, tx_hash=b"\x01\x02\x03\x04")

        # When
        data = original.to_bytes()
        recovered, _ = UpdatedWithdrawal.from_bytes(data, len(original.tx_hash))

        # Then
        assert recovered.id == original.id
        assert recovered.tx_hash == original.tx_hash

    def test_given_large_withdraw_id_when_round_tripping_then_preserves_value(self) -> None:
        # Given
        original = UpdatedWithdrawal(id=2**63 - 1, tx_hash=b"")

        # When
        recovered, _ = UpdatedWithdrawal.from_bytes(original.to_bytes(), 0)

        # Then
        assert recovered.id == original.id

    def test_given_zero_hash_length_to_bytes_when_checking_length_then_is_8_bytes(self) -> None:
        # "> Q 0s" = 8 bytes (only id)
        withdraw = UpdatedWithdrawal(id=1, tx_hash=b"")
        assert len(withdraw.to_bytes()) == 8

    def test_given_4_byte_hash_to_bytes_when_checking_length_then_is_12_bytes(self) -> None:
        # "> Q 4s" = 8 + 4 = 12 bytes
        withdraw = UpdatedWithdrawal(id=1, tx_hash=b"\x00\x01\x02\x03")
        assert len(withdraw.to_bytes()) == 12

    def test_given_from_bytes_returns_correct_bytes_consumed(self) -> None:
        withdraw = UpdatedWithdrawal(id=1, tx_hash=b"\x00" * 4)
        _, size = UpdatedWithdrawal.from_bytes(withdraw.to_bytes(), 4)
        assert size == 12


def _build_transaction_bytes(
    version: int = 1,
    command: bytes = b"u",
    chain: ChainName = ChainName.Ethereum,
    status: UpdateWithdrawMessageStatus = UpdateWithdrawMessageStatus.REJECTED,
    withdraws: list[UpdatedWithdrawal] | None = None,
    frost_sig: bytes = b"\x01" * 65,
    ecdsa_sig: bytes = b"\x02" * 65,
) -> bytes:
    """Build a complete UpdateWithdrawMessage byte payload from its components."""
    if withdraws is None:
        withdraws = [UpdatedWithdrawal(id=1, tx_hash=b"")]
    tx_hash_length = len(withdraws[0].tx_hash)
    header = pack(
        UpdateWithdrawMessage.get_header_format(),
        version,
        int.from_bytes(command),
        chain.abbreviation.encode("utf-8"),
        status.value,
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
        data = _build_transaction_bytes(command=b"x")
        with pytest.raises(UnexpectedCommandError):
            UpdateWithdrawMessage.from_bytes(data)

    def test_given_invalid_status_byte_when_calling_from_bytes_then_raises_message_format_error(
        self,
    ) -> None:
        invalid_status = 0xFF  # not a valid UpdateWithdrawStatus value
        header = pack(
            UpdateWithdrawMessage.get_header_format(),
            1,
            int.from_bytes(b"u"),
            ChainName.Ethereum.abbreviation.encode("utf-8"),
            invalid_status,
            0,
            1,
        )
        withdraw_bytes = pack(UpdatedWithdrawal.BYTES_FORMAT.format(transaction_hash_length=0), 1, b"")
        sig = pack(UpdateWithdrawMessage.get_signature_format(), self.FROST_SIG, self.ECDSA_SIG)
        data = header + withdraw_bytes + sig
        with pytest.raises(MessageFormatError, match="Invalid withdraw status"):
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
            UpdateWithdrawMessageStatus.SUCCESSFUL.value,
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
            UpdateWithdrawMessageStatus.SUCCESSFUL.value,
            tx_hash_length,
            1,  # claims 1 withdraw, but body will be empty
        )
        sig = pack(UpdateWithdrawMessage.get_signature_format(), self.FROST_SIG, self.ECDSA_SIG)
        data = header + sig  # no body
        with pytest.raises(MessageFormatError):
            UpdateWithdrawMessage.from_bytes(data)

    def test_given_valid_single_withdraw_when_calling_from_bytes_then_returns_correct_version(
        self,
    ) -> None:
        data = _build_transaction_bytes(version=3, frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert msg.version == 3

    def test_given_rejected_message_when_calling_from_bytes_then_status_is_rejected(
        self,
    ) -> None:
        data = _build_transaction_bytes(
            status=UpdateWithdrawMessageStatus.REJECTED,
            withdraws=[UpdatedWithdrawal(id=1, tx_hash=b"")],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert msg.status == UpdateWithdrawMessageStatus.REJECTED
        assert msg.transaction_hash_length == 0

    def test_given_successful_message_when_calling_from_bytes_then_status_is_successful(
        self,
    ) -> None:
        data = _build_transaction_bytes(
            status=UpdateWithdrawMessageStatus.SUCCESSFUL,
            withdraws=[UpdatedWithdrawal(id=42, tx_hash=b"\xca\xfe\xba\xbe")],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert msg.status == UpdateWithdrawMessageStatus.SUCCESSFUL
        assert msg.withdraws[0].id == 42
        assert msg.withdraws[0].tx_hash == b"\xca\xfe\xba\xbe"

    def test_given_multiple_withdraws_when_calling_from_bytes_then_returns_all_withdraws(
        self,
    ) -> None:
        withdraws = [
            UpdatedWithdrawal(id=1, tx_hash=b"\x00\x01\x02\x03"),
            UpdatedWithdrawal(id=2, tx_hash=b"\x04\x05\x06\x07"),
            UpdatedWithdrawal(id=3, tx_hash=b"\x08\x09\x0a\x0b"),
        ]
        data = _build_transaction_bytes(
            status=UpdateWithdrawMessageStatus.SUCCESSFUL,
            withdraws=withdraws,
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        msg = UpdateWithdrawMessage.from_bytes(data)
        assert len(msg.withdraws) == 3
        for original, recovered in zip(withdraws, msg.withdraws):
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
    status: UpdateWithdrawMessageStatus = UpdateWithdrawMessageStatus.REJECTED,
    withdraws: list[UpdatedWithdrawal] | None = None,
    frost_sig: bytes = b"\x01" * 65,
    ecdsa_sig: bytes = b"\x02" * 65,
) -> UpdateWithdrawMessage:
    if withdraws is None:
        withdraws = [UpdatedWithdrawal(id=1, tx_hash=b"")]
    return UpdateWithdrawMessage(
        version=version,
        chain=chain,
        status=status,
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
                status=UpdateWithdrawMessageStatus.REJECTED,
                transaction_hash_length=0,
                withdraws=[UpdatedWithdrawal(id=1, tx_hash=b"")],
                frost_signature=b"\x00" * 64,  # wrong: should be 65
            )

    def test_given_ecdsa_signature_with_wrong_length_when_creating_then_raises_value_error(
        self,
    ) -> None:
        with pytest.raises(ValueError, match="ecdsa signature"):
            UpdateWithdrawMessage(
                version=1,
                chain=ChainName.Ethereum,
                status=UpdateWithdrawMessageStatus.REJECTED,
                transaction_hash_length=0,
                withdraws=[UpdatedWithdrawal(id=1, tx_hash=b"")],
                ecdsa_signature=b"\x00" * 66,  # wrong: should be 65
            )

    def test_given_none_signatures_when_creating_then_attributes_are_none(self) -> None:
        msg = UpdateWithdrawMessage(
            version=1,
            chain=ChainName.Ethereum,
            status=UpdateWithdrawMessageStatus.REJECTED,
            transaction_hash_length=0,
            withdraws=[UpdatedWithdrawal(id=1, tx_hash=b"")],
        )
        assert msg.frost_signature is None
        assert msg.ecdsa_signature is None

    def test_given_zero_transaction_hash_length_when_creating_then_accepted(self) -> None:
        msg = UpdateWithdrawMessage(
            version=1,
            chain=ChainName.Ethereum,
            status=UpdateWithdrawMessageStatus.REJECTED,
            transaction_hash_length=0,
            withdraws=[UpdatedWithdrawal(id=1, tx_hash=b""), UpdatedWithdrawal(id=2, tx_hash=b"")],
        )
        assert msg.transaction_hash_length == 0

    def test_given_withdraw_with_mismatched_tx_hash_length_when_creating_then_raises_value_error(
        self,
    ) -> None:
        with pytest.raises(ValueError, match="All withdraw tx_hash lengths must match transaction_hash_length"):
            UpdateWithdrawMessage(
                version=1,
                chain=ChainName.Ethereum,
                status=UpdateWithdrawMessageStatus.SUCCESSFUL,
                transaction_hash_length=4,
                withdraws=[UpdatedWithdrawal(id=1, tx_hash=b"\x00" * 8)],  # 8 != 4
            )

    def test_given_multiple_withdraws_with_one_mismatched_tx_hash_when_creating_then_raises_value_error(
        self,
    ) -> None:
        with pytest.raises(ValueError, match="All withdraw tx_hash lengths must match transaction_hash_length"):
            UpdateWithdrawMessage(
                version=1,
                chain=ChainName.Ethereum,
                status=UpdateWithdrawMessageStatus.SUCCESSFUL,
                transaction_hash_length=4,
                withdraws=[
                    UpdatedWithdrawal(id=1, tx_hash=b"\x00" * 4),
                    UpdatedWithdrawal(id=2, tx_hash=b"\x00" * 6),  # 6 != 4
                ],
            )

    def test_given_valid_signatures_when_creating_then_stored_correctly(self) -> None:
        frost = b"\xaa" * 65
        ecdsa = b"\xbb" * 65
        msg = UpdateWithdrawMessage(
            version=7,
            chain=ChainName.Ethereum,
            status=UpdateWithdrawMessageStatus.SUCCESSFUL,
            transaction_hash_length=4,
            withdraws=[UpdatedWithdrawal(id=99, tx_hash=b"\x00" * 4)],
            frost_signature=frost,
            ecdsa_signature=ecdsa,
        )
        assert msg.version == 7
        assert msg.status == UpdateWithdrawMessageStatus.SUCCESSFUL
        assert msg.frost_signature == frost
        assert msg.ecdsa_signature == ecdsa
        assert msg._transaction_bytes is None


class TestUpdateWithdrawMessageFormatMethods:
    def test_get_header_format_calcsize_matches_header_length(self) -> None:
        assert calcsize(UpdateWithdrawMessage.get_header_format()) == UpdateWithdrawMessage.HEADER_LENGTH

    def test_get_body_format_with_zero_hash_length_calcsize_is_8(self) -> None:
        # "> Q 0s" = 8 bytes when transaction_hash_length == 0 (rejected)
        assert calcsize(UpdateWithdrawMessage.get_body_format(0)) == 8

    def test_get_body_format_calcsize_matches_withdraw_to_bytes_length(self) -> None:
        tx_hash_length = 4
        withdraw = UpdatedWithdrawal(id=1, tx_hash=b"\x00" * tx_hash_length)
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

    def test_str_contains_status(self) -> None:
        msg = _build_message(status=UpdateWithdrawMessageStatus.REJECTED)
        assert f"status: {UpdateWithdrawMessageStatus.REJECTED}" in str(msg)  

    def test_str_contains_transaction_hash_length(self) -> None:
        withdraw = UpdatedWithdrawal(id=1, tx_hash=b"\x00" * 8)
        msg = _build_message(status=UpdateWithdrawMessageStatus.SUCCESSFUL, withdraws=[withdraw])
        assert "transaction_hash_length: 8" in str(msg)


class TestUpdateWithdrawMessageToBytes:
    FROST_SIG = b"\x01" * 65
    ECDSA_SIG = b"\x02" * 65

    def test_given_cached_transaction_bytes_when_calling_to_bytes_then_returns_cached(
        self,
    ) -> None:
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
    """Round-trip consistency: to_bytes ↔ from_bytes."""

    FROST_SIG = b"\x01" * 65
    ECDSA_SIG = b"\x02" * 65

    def test_given_rejected_message_when_round_tripping_then_fields_match(self) -> None:
        # Given
        original = _build_message(
            version=2,
            status=UpdateWithdrawMessageStatus.REJECTED,
            withdraws=[UpdatedWithdrawal(id=77, tx_hash=b"")],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        assert original._transaction_bytes is None

        # When
        recovered = UpdateWithdrawMessage.from_bytes(original.to_bytes())

        # Then
        assert recovered.version == original.version
        assert recovered.status == UpdateWithdrawMessageStatus.REJECTED
        assert recovered.transaction_hash_length == 0
        assert recovered.withdraws[0].id == 77
        assert recovered.withdraws[0].tx_hash == b""

    def test_given_successful_message_when_round_tripping_then_fields_match(self) -> None:
        # Given
        original = _build_message(
            version=3,
            status=UpdateWithdrawMessageStatus.SUCCESSFUL,
            withdraws=[UpdatedWithdrawal(id=42, tx_hash=b"\xde\xad\xbe\xef")],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        assert original._transaction_bytes is None

        # When
        recovered = UpdateWithdrawMessage.from_bytes(original.to_bytes())

        # Then
        assert recovered.version == original.version
        assert recovered.status == UpdateWithdrawMessageStatus.SUCCESSFUL
        assert recovered.transaction_hash_length == 4
        assert recovered.withdraws[0].id == 42
        assert recovered.withdraws[0].tx_hash == b"\xde\xad\xbe\xef"

    def test_given_message_when_to_bytes_then_from_bytes_then_to_bytes_then_bytes_are_equal(
        self,
    ) -> None:
        # Given
        original = _build_message(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        assert original._transaction_bytes is None

        # When
        first_bytes = original.to_bytes()
        second_bytes = UpdateWithdrawMessage.from_bytes(first_bytes).to_bytes()

        # Then
        assert first_bytes == second_bytes

    def test_given_bytes_parsed_via_from_bytes_when_calling_to_bytes_then_from_bytes_then_fields_match(
        self,
    ) -> None:
        # Given
        data = _build_transaction_bytes(
            version=5,
            status=UpdateWithdrawMessageStatus.SUCCESSFUL,
            withdraws=[UpdatedWithdrawal(id=123, tx_hash=b"\xca\xfe\xba\xbe")],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        first = UpdateWithdrawMessage.from_bytes(data)
        assert first._transaction_bytes is not None

        # When
        recovered = UpdateWithdrawMessage.from_bytes(first.to_bytes())

        # Then
        assert recovered.version == first.version
        assert recovered.status == first.status
        assert recovered.transaction_hash_length == first.transaction_hash_length
        assert recovered.withdraws[0].id == first.withdraws[0].id
        assert recovered.withdraws[0].tx_hash == first.withdraws[0].tx_hash

    def test_given_bytes_parsed_and_cache_cleared_when_round_tripping_then_fields_match(
        self,
    ) -> None:
        # Given
        data = _build_transaction_bytes(
            version=5,
            status=UpdateWithdrawMessageStatus.SUCCESSFUL,
            withdraws=[UpdatedWithdrawal(id=123, tx_hash=b"\xca\xfe\xba\xbe")],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        first = UpdateWithdrawMessage.from_bytes(data)
        first._transaction_bytes = None

        # When
        recovered = UpdateWithdrawMessage.from_bytes(first.to_bytes())

        # Then
        assert recovered.status == first.status
        assert recovered.transaction_hash_length == first.transaction_hash_length
        assert recovered.withdraws[0].id == first.withdraws[0].id
        assert recovered.withdraws[0].tx_hash == first.withdraws[0].tx_hash


class TestUpdateWithdrawMessageCreateMessage:
    FROST_SIG = b"\x01" * 65
    ECDSA_SIG = b"\x02" * 65

    def test_given_rejected_single_withdraw_when_calling_create_message_then_length_matches(
        self,
    ) -> None:
        withdraw = UpdatedWithdrawal(id=1, tx_hash=b"")
        msg = _build_message(
            status=UpdateWithdrawMessageStatus.REJECTED,
            withdraws=[withdraw],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        expected_length = UpdateWithdrawMessage.HEADER_LENGTH + len(withdraw.to_bytes())
        assert len(msg.create_message()) == expected_length

    def test_given_successful_single_withdraw_when_calling_create_message_then_length_matches(
        self,
    ) -> None:
        withdraw = UpdatedWithdrawal(id=1, tx_hash=b"\xde\xad\xbe\xef")
        msg = _build_message(
            status=UpdateWithdrawMessageStatus.SUCCESSFUL,
            withdraws=[withdraw],
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
        expected_length = UpdateWithdrawMessage.HEADER_LENGTH + len(withdraw.to_bytes())
        assert len(msg.create_message()) == expected_length

    def test_given_multiple_withdraws_when_calling_create_message_then_length_includes_all_bodies(
        self,
    ) -> None:
        withdraws = [UpdatedWithdrawal(id=i, tx_hash=b"\x00" * 4) for i in range(3)]
        msg = _build_message(
            status=UpdateWithdrawMessageStatus.SUCCESSFUL,
            withdraws=withdraws,
            frost_sig=self.FROST_SIG,
            ecdsa_sig=self.ECDSA_SIG,
        )
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
            assert msg._verify_frost_signature("some_frost_public_key") is True

    def test_given_curve_returns_false_when_verifying_frost_then_returns_false(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch("zex.transactions.update_withdraw_message.curve") as mock_curve:
            mock_curve.single_verify.return_value = False
            assert msg._verify_frost_signature("some_frost_public_key") is False

    def test_given_valid_call_when_verifying_frost_then_calls_single_verify_with_correct_args(
        self,
    ) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        expected_message = data[: -UpdateWithdrawMessage.SIGNATURE_LENGTH]
        with patch("zex.transactions.update_withdraw_message.curve") as mock_curve:
            mock_curve.single_verify.return_value = True
            msg._verify_frost_signature("my_frost_key")
            mock_curve.single_verify.assert_called_once_with(
                self.FROST_SIG.hex(), expected_message, "my_frost_key"
            )


class TestUpdateWithdrawMessageVerifyEcdsaSignature:
    FROST_SIG = b"\xaa" * 65
    ECDSA_SIG = b"\xbb" * 65

    def test_given_recovered_address_matches_when_verifying_ecdsa_then_returns_true(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch("zex.transactions.update_withdraw_message.Account") as mock_account, patch(
            "zex.transactions.update_withdraw_message.encode_defunct"
        ):
            mock_account.recover_message.return_value = "0xShieldAddress"
            assert msg._verify_ecdsa_signature("0xShieldAddress") is True

    def test_given_recovered_address_does_not_match_when_verifying_ecdsa_then_returns_false(
        self,
    ) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch("zex.transactions.update_withdraw_message.Account") as mock_account, patch(
            "zex.transactions.update_withdraw_message.encode_defunct"
        ):
            mock_account.recover_message.return_value = "0xDifferentAddress"
            assert msg._verify_ecdsa_signature("0xShieldAddress") is False

    def test_given_valid_call_when_verifying_ecdsa_then_calls_recover_message_with_correct_args(
        self,
    ) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        expected_message = data[: -UpdateWithdrawMessage.SIGNATURE_LENGTH]
        with patch("zex.transactions.update_withdraw_message.Account") as mock_account, patch(
            "zex.transactions.update_withdraw_message.encode_defunct"
        ) as mock_encode_defunct:
            mock_account.recover_message.return_value = "0xShieldAddress"
            msg._verify_ecdsa_signature("0xShieldAddress")
            mock_encode_defunct.assert_called_once_with(expected_message)
            mock_account.recover_message.assert_called_once_with(
                mock_encode_defunct.return_value, signature=self.ECDSA_SIG
            )


class TestUpdateWithdrawMessageVerifySignature:
    FROST_SIG = b"\xcc" * 65
    ECDSA_SIG = b"\xdd" * 65

    def test_given_both_signatures_valid_when_verifying_then_returns_true(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch.object(msg, "_verify_frost_signature", return_value=True), patch.object(
            msg, "_verify_ecdsa_signature", return_value=True
        ):
            assert msg.verify_signature(b"", "frost_key", "shield_address") is True

    def test_given_frost_signature_invalid_when_verifying_then_returns_false(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch.object(msg, "_verify_frost_signature", return_value=False), patch.object(
            msg, "_verify_ecdsa_signature", return_value=True
        ):
            assert msg.verify_signature(b"", "frost_key", "shield_address") is False

    def test_given_ecdsa_signature_invalid_when_verifying_then_returns_false(self) -> None:
        data = _build_transaction_bytes(frost_sig=self.FROST_SIG, ecdsa_sig=self.ECDSA_SIG)
        msg = UpdateWithdrawMessage.from_bytes(data)
        with patch.object(msg, "_verify_frost_signature", return_value=True), patch.object(
            msg, "_verify_ecdsa_signature", return_value=False
        ):
            assert msg.verify_signature(b"", "frost_key", "shield_address") is False
