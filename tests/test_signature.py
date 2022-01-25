from eip712_structs import Address, EIP712Struct, String, make_domain
from eth_account.account import Account
from eth_utils.crypto import keccak


class Person(EIP712Struct):
    name = String()
    wallet = Address()


class Mail(EIP712Struct):
    ...


setattr(Mail, "from", Person)
setattr(Mail, "to", Person)
setattr(Mail, "contents", String())

domain = make_domain("Ether Mail", "1", 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")


def test_EIP712_hashing_and_signing() -> None:
    data = Mail(
        **{
            "from": Person(
                name="Cow", wallet="0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
            ),
            "to": Person(
                name="Bob", wallet="0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            ),
            "contents": "Hello, Bob!",
        }
    )

    v = 28
    r = 0x4355C47D63924E8A72E509B65029052EB6C299D53A04E167C5775FD466751C9D
    s = 0x07299936D304C153F6443DFA05F40FF007D72911B6F72307F996231605B91562

    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + v.to_bytes(1, "big")

    signable_message = data.signable_bytes(domain)
    domain_separator_expected = (
        0xF2CEE375FA42B42143804025FC449DEAFD50CC031CA257E0B194A650A912090F
    )
    message_hash = 0xC52C0EE5D84264471806290A3F2C4CECFC5490626BF912D01F240D7A274B371E

    assert signable_message[:2] == b"\x19\x01"
    assert signable_message[2:34] == domain_separator_expected.to_bytes(32, "big")
    assert signable_message[34:] == message_hash.to_bytes(32, "big")

    message_hash = keccak(signable_message)

    recovered_address = Account._recover_hash(message_hash, vrs=(v, r, s))
    assert recovered_address == "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"

    recovered_address = Account._recover_hash(message_hash, signature=signature)
    assert recovered_address == "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
