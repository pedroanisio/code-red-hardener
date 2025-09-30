"""Custom exceptions for SSH Hardener."""


class HardenerError(Exception):
    """Base exception for all hardener errors."""

    pass


class ConfigurationError(HardenerError):
    """Raised when configuration is invalid."""

    pass


class SystemRequirementError(HardenerError):
    """Raised when system requirements are not met."""

    pass


class ValidationError(HardenerError):
    """Raised when validation fails."""

    pass


class CommandExecutionError(HardenerError):
    """Raised when command execution fails."""

    pass


class RollbackError(HardenerError):
    """Raised when rollback operation fails."""

    pass


class ServiceControlError(HardenerError):
    """Raised when service control operation fails."""

    pass