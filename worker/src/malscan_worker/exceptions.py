"""Domain exceptions for worker archive handling."""


class ArchivePasswordRequiredError(Exception):
    """Raised when an archive requires a password but none was provided."""


class ArchiveWrongPasswordError(Exception):
    """Raised when an archive password was provided but is invalid."""
