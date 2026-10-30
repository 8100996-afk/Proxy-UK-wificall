def create_app(*args, **kwargs):
    """Load the web application only when a caller explicitly requests it."""
    from .app import create_app as factory

    return factory(*args, **kwargs)

__all__ = ["create_app"]

