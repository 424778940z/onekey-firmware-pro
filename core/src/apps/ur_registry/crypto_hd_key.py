# https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md

from trezor import wire
from trezor.crypto import base58

from .crypto_coin_info import CryptoCoinInfo
from .crypto_key_path import CryptoKeyPath
from .ur_py.ur.cbor_lite import CBORDecoder, CBOREncoder
from .ur_py.ur.ur import UR
from .ur_py.ur.ur_encoder import UREncoder

IS_MASTER = 1
IS_PRIVATE = 2
KEY_DATA = 3
CHAIN_CODE = 4
USE_INFO = 5
ORIGIN = 6
CHILDREN = 7
PARENT_FINGERPRINT = 8
NAME = 9
NOTE = 10


class CryptoHDKey:
    def __init__(self):
        self.is_master = None
        self.is_private_key = None
        self.key = None
        self.chain_code = None
        self.use_info = None
        self.origin = None
        self.children = None
        self.parent_fingerprint = None
        self.name = None
        self.note = None

    @staticmethod
    def get_registry_type():
        return "crypto-hdkey"

    @staticmethod
    def get_tag():
        return 303

    def new_master_key(self, key: bytes, chain_code: bytes):
        self.is_master = True
        self.is_private_key = None
        self.key = key
        self.chain_code = chain_code
        self.use_info = None
        self.origin = None
        self.children = None
        self.parent_fingerprint = None
        self.name = None
        self.note = None

    def new_extended_key(
        self,
        is_private_key: bool,
        key: bytes,
        chain_code: bytes,
        use_info: CryptoCoinInfo | None,
        origin: CryptoKeyPath | None,
        children: CryptoKeyPath | None,
        parent_fingerprint: int | None,
        name: str | None,
        note: str | None,
    ):
        self.is_master = False
        self.is_private_key = is_private_key
        self.key = key
        self.chain_code = chain_code
        self.use_info = use_info
        self.origin = origin
        self.children = children
        self.parent_fingerprint = parent_fingerprint
        self.name = name
        self.note = note

    def get_is_master(self) -> bool:
        return self.is_master if self.is_master is not None else False

    def get_is_private_key(self) -> bool:
        return self.is_private_key if self.is_private_key is not None else False

    def get_key(self) -> bytes:
        return self.key if self.key is not None else b""

    def get_chain_code(self) -> bytes:
        return self.chain_code if self.chain_code is not None else b""

    def get_use_info(self) -> CryptoCoinInfo | None:
        return self.use_info

    def get_origin(self) -> CryptoKeyPath | None:
        return self.origin

    def get_children(self) -> CryptoKeyPath | None:
        return self.children

    def get_parent_fingerprint(self) -> int:
        return self.parent_fingerprint or 0

    def get_name(self) -> str:
        return self.name if self.name is not None else ""

    def get_note(self) -> str:
        return self.note if self.note is not None else ""

    def get_bip32_key(self) -> str:
        key = self.get_key()
        chain_code = (
            self.get_chain_code() if self.get_chain_code() is not None else bytes(32)
        )
        parent_fingerprint = self.get_parent_fingerprint() or 0

        depth = 0
        index = 0
        if self.get_is_master() is True:
            version = [0x04, 0x88, 0xAD, 0xE4]
            depth = 0
            index = 0
        else:
            origin = self.get_origin()
            if origin is not None:
                depth = len(origin.get_components()) if origin is not None else 0
                index = (
                    origin.get_components()[-1].get_canonical_index()
                    if origin is not None
                    else 0
                )
            if self.get_is_private_key() is True:
                version = [0x04, 0x88, 0xAD, 0xE4]
            else:
                version = [0x04, 0x88, 0xB2, 0x1E]

        output = bytearray(b"")
        output.extend(bytes(version))  # 4
        output.extend(depth.to_bytes(1, "big"))  # 1
        output.extend(parent_fingerprint.to_bytes(4, "big"))  # 4
        output.extend(index.to_bytes(4, "big"))  # 4
        output.extend(chain_code)  # 32
        output.extend(key)  # 33
        return base58.encode_check(bytes(output))

    def get_account_index(self):
        if __debug__:
            print("todo - get_account_index")

    def get_map_size(self):
        size = 1 + sum(
            (
                self.is_private_key is not None,
                self.chain_code is not None,
                self.use_info is not None,
                self.origin is not None,
                self.children is not None,
                self.parent_fingerprint is not None,
                self.name is not None,
                self.note is not None,
            )
        )
        return size

    def cbor_encode(self):
        encoder = CBOREncoder()
        if self.is_master is True:
            encoder.encodeMapSize(3)
            encoder.encodeInteger(IS_MASTER)
            encoder.encodeBool(self.is_master)
            encoder.encodeInteger(KEY_DATA)
            encoder.encodeBytes(self.key)
            encoder.encodeInteger(CHAIN_CODE)
            encoder.encodeBytes(self.chain_code)
        else:
            size = self.get_map_size()
            encoder.encodeMapSize(size)
            if self.is_private_key is not None:
                encoder.encodeInteger(IS_PRIVATE)
                encoder.encodeBool(self.is_private_key)

            encoder.encodeInteger(KEY_DATA)
            encoder.encodeBytes(self.key)

            if self.chain_code is not None:
                encoder.encodeInteger(CHAIN_CODE)
                encoder.encodeBytes(self.chain_code)

            if self.use_info is not None:
                encoder.encodeInteger(USE_INFO)
                encoder.encodeTag(CryptoCoinInfo.get_tag())
                cbor = self.use_info.cbor_encode()
                encoder.cborExtend(cbor)

            if self.origin is not None:
                encoder.encodeInteger(ORIGIN)
                encoder.encodeTag(CryptoKeyPath.get_tag())
                cbor = self.origin.cbor_encode()
                encoder.cborExtend(cbor)

            if self.children is not None:
                encoder.encodeInteger(CHILDREN)
                encoder.encodeTag(CryptoKeyPath.get_tag())
                cbor = self.children.cbor_encode()
                encoder.cborExtend(cbor)

            if self.parent_fingerprint is not None:
                encoder.encodeInteger(PARENT_FINGERPRINT)
                encoder.encodeInteger(self.parent_fingerprint)

            if self.name is not None:
                encoder.encodeInteger(NAME)
                encoder.encodeText(self.name)

            if self.note is not None:
                encoder.encodeInteger(NOTE)
                encoder.encodeText(self.note)

        return encoder.get_bytes()

    def ur_encode(self):
        data = self.cbor_encode()
        return UR(CryptoHDKey.get_registry_type(), data)

    @staticmethod
    def from_cbor(cbor):
        decoder = CBORDecoder(cbor)
        return CryptoHDKey.decode(decoder)

    @staticmethod
    def decode(decoder: CBORDecoder):
        key_path = CryptoHDKey()
        size, _ = decoder.decodeMapSize()
        for _ in range(size):
            key, _ = decoder.decodeInteger()
            if key == IS_MASTER:
                key_path.is_master, _ = decoder.decodeBool()
            elif key == IS_PRIVATE:
                key_path.is_private_key, _ = decoder.decodeBool()
            elif key == KEY_DATA:
                key_path.key, _ = decoder.decodeBytes()
            elif key == CHAIN_CODE:
                key_path.chain_code, _ = decoder.decodeBytes()
            elif key == USE_INFO:
                tag, _ = decoder.decodeTag()
                if tag != CryptoCoinInfo.get_tag():
                    raise Exception(f"Expected Tag {tag}")
                key_path.use_info = CryptoCoinInfo.decode(decoder)
            elif key == ORIGIN:
                tag, _ = decoder.decodeTag()
                if tag != CryptoKeyPath.get_tag():
                    raise Exception(f"Expected Tag {tag}")
                key_path.origin = CryptoKeyPath.decode(decoder)
            elif key == CHILDREN:
                tag, _ = decoder.decodeTag()
                if tag != CryptoKeyPath.get_tag():
                    raise Exception(f"Expected Tag {tag}")
                key_path.children = CryptoKeyPath.decode(decoder)
            elif key == PARENT_FINGERPRINT:
                value, _ = decoder.decodeInteger()
                key_path.parent_fingerprint = list(value.to_bytes(4, "big"))
            elif key == NAME:
                key_path.name, _ = decoder.decodeText()
            elif key == NOTE:
                key_path.note, _ = decoder.decodeText()
            else:
                raise Exception(f"Expected key {key}")
        return key_path


async def genCryptoHDKeyForETHStandard(ctx: wire.Context) -> str:
    from trezor.messages import GetPublicKey
    from apps.bitcoin import get_public_key as bitcoin_get_public_key
    from apps.common import paths
    from . import helpers
    from apps.common import passphrase

    if passphrase.is_enabled():
        wire.QR_CONTEXT.passphrase = None

    # "m/44'/60'/0'"
    btc_pubkey_msg = GetPublicKey(
        address_n=paths.parse_path(helpers.ETH_STANDARD_PREFIX)
    )
    resp = await bitcoin_get_public_key.get_public_key(ctx, btc_pubkey_msg)
    hdkey = helpers.generate_hdkey_ETHStandard(ctx, resp)
    ur = hdkey.ur_encode()
    encoded = UREncoder.encode(ur)
    return encoded.upper()
