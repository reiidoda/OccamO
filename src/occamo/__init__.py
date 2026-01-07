from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__ = version("occamo")
except PackageNotFoundError:  # pragma: no cover - fallback for editable source trees
    __version__ = "0.1.0"
