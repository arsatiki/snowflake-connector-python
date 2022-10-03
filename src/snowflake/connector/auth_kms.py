#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import abc
import base64
import hashlib
import json
import os
from calendar import timegm
from datetime import datetime, timedelta
from logging import getLogger

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .auth_by_plugin import AuthByPlugin
from .errorcode import (
    ER_CONNECTION_TIMEOUT,
    ER_FAILED_TO_CONNECT_TO_DB,
    ER_INVALID_PRIVATE_KEY,
)
from .errors import OperationalError, ProgrammingError
from .network import KEY_PAIR_AUTHENTICATOR

logger = getLogger(__name__)


class AuthByKMS(AuthByPlugin):
    """Key management system based authentication."""

    ALGORITHM = "RS256"
    ISSUER = "iss"
    SUBJECT = "sub"
    EXPIRE_TIME = "exp"
    ISSUE_TIME = "iat"
    LIFETIME = 60
    DEFAULT_JWT_RETRY_ATTEMPTS = 10
    DEFAULT_JWT_CNXN_WAIT_TIME = 10

    def __init__(self, key_manager, lifetime_in_seconds: int = LIFETIME):
        super().__init__()
        self._key_manager = key_manager
        self._jwt_token = ""
        self._jwt_token_exp = 0
        self._lifetime = timedelta(
            seconds=int(os.getenv("JWT_LIFETIME_IN_SECONDS", lifetime_in_seconds))
        )
        self._jwt_retry_attempts = int(
            os.getenv(
                "JWT_CNXN_RETRY_ATTEMPTS", AuthByKMS.DEFAULT_JWT_RETRY_ATTEMPTS
            )
        )
        self._jwt_cnxn_wait_time = timedelta(
            seconds=int(
                os.getenv(
                    "JWT_CNXN_WAIT_TIME", AuthByKMS.DEFAULT_JWT_CNXN_WAIT_TIME
                )
            )
        )
        self._current_retry_count = 0

    def authenticate(
        self,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str | None,
    ) -> str:
        if ".global" in account:
            account = account.partition("-")[0]
        else:
            account = account.partition(".")[0]
        account = account.upper()
        user = user.upper()

        now = datetime.utcnow()

        public_key_fp = self.calculate_public_key_fingerprint()

        self._jwt_token_exp = now + self._lifetime
        payload = {
            self.ISSUER: f"{account}.{user}.{public_key_fp}",
            self.SUBJECT: f"{account}.{user}",
            self.ISSUE_TIME: now,
            self.EXPIRE_TIME: self._jwt_token_exp,
        }

        _jwt_token = self.jwt_encode(payload)

        # jwt.encode() returns bytes in pyjwt 1.x and a string
        # in pyjwt 2.x
        if isinstance(_jwt_token, bytes):
            self._jwt_token = _jwt_token.decode("utf-8")
        else:
            self._jwt_token = _jwt_token

        return self._jwt_token

    def jwt_encode(self, payload):
        headers_json = b'{"alg":"RS256","typ":"JWT"}'
        headers_b64 = base64.b64encode(headers_json)

        payload = payload.copy()
        for time_claim in ["exp", "iat", "nbf"]:
            # Convert datetime to a intDate value in known time-format claims
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(payload[time_claim].utctimetuple())
        payload_json = json.dumps(payload, separators=(",", ":")).encode('utf-8')
        payload_b64 = base64.b64encode(payload_json)

        message = headers_b64 + b'.' + payload_b64
        signature = self._key_manager.sign(message)
        return message + b'.' + base64.b64encode(signature)

    def calculate_public_key_fingerprint(self):
        # get public key bytes
        public_key = self._key_manager.public_key()
        public_key_der = public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )

        # take sha256 on raw bytes and then do base64 encode
        sha256hash = hashlib.sha256()
        sha256hash.update(public_key_der)

        public_key_fp = "SHA256:" + base64.b64encode(sha256hash.digest()).decode(
            "utf-8"
        )
        logger.debug("Public key fingerprint is %s", public_key_fp)

        return public_key_fp

    def update_body(self, body):
        body["data"]["AUTHENTICATOR"] = KEY_PAIR_AUTHENTICATOR
        body["data"]["TOKEN"] = self._jwt_token

    def assertion_content(self):
        return self._jwt_token

    def should_retry(self, count: int) -> bool:
        return count < self._jwt_retry_attempts

    def get_timeout(self) -> int:
        return self._jwt_cnxn_wait_time.seconds

    def handle_timeout(
        self,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str | None,
    ) -> None:
        if self._retry_ctx.get_current_retry_count() > self._jwt_retry_attempts:
            logger.debug("Exhausted max login attempts. Aborting connection")
            self._retry_ctx.reset()
            raise OperationalError(
                msg=f"Could not connect to Snowflake backend after {self._retry_ctx.get_current_retry_count()} attempt(s)."
                "Aborting",
                errno=ER_FAILED_TO_CONNECT_TO_DB,
            )
        else:
            logger.debug(
                f"Hit JWT timeout, attempt {self._retry_ctx.get_current_retry_count()}. Retrying..."
            )
            self._retry_ctx.increment_retry()

        self.authenticate(authenticator, service_name, account, user, password)

    def can_handle_exception(self, op: OperationalError) -> bool:
        if op.errno is ER_CONNECTION_TIMEOUT:
            return True
        return False


class KeyManager(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def public_key(self) -> RSAPublicKey:
        pass

    @abc.abstractmethod
    def sign(message: bytes) -> bytes:
        pass
