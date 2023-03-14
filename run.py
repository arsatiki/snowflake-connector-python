from hashlib import sha256

from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import SignatureAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicNumbers,
)
from cryptography.hazmat.primitives.serialization import load_der_private_key

import snowflake.connector
from snowflake.connector.auth_kms import KeyManager
from snowflake.connector.errorcode import ER_INVALID_PRIVATE_KEY
from snowflake.connector.errors import ProgrammingError

# message (bytes) -> signature (bytes)


class AzureKeyVaultManager(KeyManager):
    def __init__(self, kvclient, keyname):
        self._kvclient = kvclient
        self._keyname = keyname

    def public_key(self):
        pubkey = self._kvclient.get_key(self._keyname)
        e = int.from_bytes(pubkey.key.e, 'big')
        n = int.from_bytes(pubkey.key.n, 'big')
        rsakey = RSAPublicNumbers(e, n)
        return rsakey.public_key()

    def sign(self, message):
        cc = self._kvclient.get_cryptography_client(self._keyname)
        hash = sha256(message).digest()
        result = cc.sign(SignatureAlgorithm.rs256, hash)
        return result.signature


class PEMFileManager(KeyManager):
    def __init__(self, private_key):
        try:
            self._private_key = load_der_private_key(
                data=private_key, password=None, backend=default_backend()
            )
        except Exception as e:
            raise ProgrammingError(
                msg="Failed to load private key: {}\nPlease provide a valid unencrypted rsa private "
                "key in DER format as bytes object".format(str(e)),
                errno=ER_INVALID_PRIVATE_KEY,
            )

        if not isinstance(private_key, RSAPrivateKey):
            raise ProgrammingError(
                msg="Private key type ({}) not supported.\nPlease provide a valid rsa private "
                "key in DER format as bytes object".format(
                    private_key.__class__.__name__
                ),
                errno=ER_INVALID_PRIVATE_KEY,
            )

    def public_key(self):
        return self._private_key.public_key()

    def sign(self, message):
        signature = self._private_key.sign(message, padding.PKCS1v15(), sha256)
        return signature


if __name__ == '__main__':
    credential = DefaultAzureCredential(additionally_allowed_tenants=['*'])
    kc = KeyClient('https://xxxxxxx.vault.azure.net/', credential)

    # Gets the version
    ctx = snowflake.connector.connect(
        user='foo@bar.com',
        key_manager=AzureKeyVaultManager(kc, 'testkey'),
        authenticator='KMS',
        account='df99999.west-europe.azure',
        warehouse='compute_wh',
        database='public',
    )

    with ctx.cursor() as cs:
        cs.execute("SELECT current_version()")
        one_row = cs.fetchone()
        print(one_row[0])
    ctx.close()
