import warnings
from copy import copy
from decimal import Decimal
from binascii import unhexlify
from typing import TYPE_CHECKING, Any, Dict, Sequence, Tuple

from . import exceptions, messages
from .tools import expect, session

if TYPE_CHECKING:
    from .client import TrezorClient

from .messages_special.DataSignature import DataSignature
from .messages_special.DigestSignature import DigestSignature
from .messages_special.Ed25519Nonce import Ed25519Nonce
from .messages_special.Ed25519PublicKey import Ed25519PublicKey
from .messages_special.Ed25519Signature import Ed25519Signature
from .messages_special.Ed25519Verify import Ed25519Verify
from .messages_special.ExportEd25519PublicKey import ExportEd25519PublicKey
from .messages_special.GetEd25519Nonce import GetEd25519Nonce
from .messages_special.SignData import SignData
from .messages_special.SignDigest import SignDigest
from .messages_special.CosignEd25519 import CosignEd25519


@expect(DigestSignature)
def sign_digest(
    client, coin_name, n, digest
):
    return client.call(
        SignDigest(
            coin_name=coin_name,
            address_n=n,
            digest=digest
        )
    )

@expect(DataSignature)
def sign_data(
    client, coin_name, n, data
):
    return client.call(
        SignData(
            coin_name=coin_name,
            address_n=n,
            data=data
        )
    )

@expect(Ed25519PublicKey)
def export_ed25519_pubkey(
    client, n
):
    return client.call(
        ExportEd25519PublicKey(
            address_n=n
        )
    )

@expect(Ed25519Nonce)
def get_ed25519_nonce(
    client, n, data, ctr
):
    return client.call(
        GetEd25519Nonce(
            address_n=n,
            data=data,
            ctr=ctr
        )
    )

@expect(Ed25519Signature)
def cosign_ed25519(
    client, n, digest, ctr, global_pubkey, global_commit
):
    return client.call(
        CosignEd25519(
            address_n=n,
            digest=digest,
            ctr=ctr,
            global_pubkey=global_pubkey,
            global_commit=global_commit
        )
    )

@expect(messages.Success, field="message")
def ed25519_verify(
    client, digest, pubkey, sig
):
    return client.call(
        Ed25519Verify(
            digest=digest,
            pubkey=pubkey,
            sig=sig
        )
    )
