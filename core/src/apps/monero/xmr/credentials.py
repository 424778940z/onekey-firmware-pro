from trezor.enums import MoneroNetworkType

from apps.monero.xmr import crypto, crypto_helpers
from apps.monero.xmr.addresses import encode_addr
from apps.monero.xmr.networks import net_version


class AccountCreds:
    """
    Stores account private keys
    """

    def __init__(
        self,
        view_key_private: crypto.Scalar,
        spend_key_private: crypto.Scalar,
        view_key_public: crypto.Point,
        spend_key_public: crypto.Point,
        address: str,
        network_type: MoneroNetworkType,
    ) -> None:
        self.view_key_private = view_key_private
        self.view_key_public = view_key_public
        self.spend_key_private = spend_key_private
        self.spend_key_public = spend_key_public
        self.address: str | None = address
        self.network_type: MoneroNetworkType | None = network_type

    @classmethod
    def new_wallet(
        cls,
        priv_view_key: crypto.Scalar,
        priv_spend_key: crypto.Scalar,
        network_type: MoneroNetworkType = MoneroNetworkType.MAINNET,
    ) -> "AccountCreds":
        pub_view_key = crypto.scalarmult_base_into(None, priv_view_key)
        pub_spend_key = crypto.scalarmult_base_into(None, priv_spend_key)
        addr = encode_addr(
            net_version(network_type),
            crypto_helpers.encodepoint(pub_spend_key),
            crypto_helpers.encodepoint(pub_view_key),
        )
        return cls(
            view_key_private=priv_view_key,
            spend_key_private=priv_spend_key,
            view_key_public=pub_view_key,
            spend_key_public=pub_spend_key,
            address=addr,
            network_type=network_type,
        )

    @classmethod
    def new_wallet_ex(
        cls,
        priv_view_key: crypto.Scalar,
        priv_spend_key: crypto.Scalar,
        pub_view_key: crypto.Point,
        pub_spend_key: crypto.Point,
        network_type: MoneroNetworkType = MoneroNetworkType.MAINNET,
    ) -> "AccountCreds":
        addr = encode_addr(
            net_version(network_type),
            crypto_helpers.encodepoint(pub_spend_key),
            crypto_helpers.encodepoint(pub_view_key),
        )
        return cls(
            view_key_private=priv_view_key,
            spend_key_private=priv_spend_key,
            view_key_public=pub_view_key,
            spend_key_public=pub_spend_key,
            address=addr,
            network_type=network_type,
        )
