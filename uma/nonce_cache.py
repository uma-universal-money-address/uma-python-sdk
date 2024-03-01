# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict
from uma.exceptions import InvalidNonceException


class INonceCache(ABC):
    @abstractmethod
    def check_and_save_nonce(self, nonce: str, timestamp: datetime) -> None:
        """
        Checks if the given nonce has been used before, and if not, saves it.
        If the nonce has been used before, or if timestamp is too old, raises InvalidNonceException.

        Args:
            nonce: the nonce to cache.
            timestamp: timestamp corresponding to the nonce.
        """

    @abstractmethod
    def purge_nonces_older_than(self, timestamp: datetime) -> None:
        """
        Purges all nonces older than the given timestamp. This allows the cache to be pruned.

        Args:
            timestamp: the timestamp before which nonces should be removed.
        """


class InMemoryNonceCache(INonceCache):
    """
    InMemoryNonceCache is an in-memory implementation of NonceCache.
    It is not recommended to use this in production, as it will not persist across restarts. You likely want to
    implement your own NonceCache that persists to a database of some sort.
    """

    def __init__(self, oldest_valid_timestamp: datetime) -> None:
        self._cache: Dict[str, datetime] = {}
        self._oldest_valid_timestamp = oldest_valid_timestamp

    def check_and_save_nonce(self, nonce: str, timestamp: datetime) -> None:
        if timestamp < self._oldest_valid_timestamp:
            raise InvalidNonceException("Timestamp is too old.")
        if nonce in self._cache:
            raise InvalidNonceException("Nonce has already been used.")
        self._cache[nonce] = timestamp

    def purge_nonces_older_than(self, timestamp: datetime) -> None:
        expired_nonces = [nonce for nonce, ts in self._cache.items() if ts < timestamp]
        for nonce in expired_nonces:
            del self._cache[nonce]
        self._oldest_valid_timestamp = timestamp
