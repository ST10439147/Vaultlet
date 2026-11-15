class VaultletError(Exception):
    """Base class for errors raised by Vaultlet."""


class WrongPassword(VaultletError):
    """The master password did not unlock the vault."""


class CorruptVault(VaultletError):
    """The vault file is malformed or failed authentication."""


class EntryNotFound(VaultletError):
    """No entry with the given id exists in the vault."""
