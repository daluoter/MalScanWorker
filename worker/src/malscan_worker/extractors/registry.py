# worker/src/malscan_worker/extractors/registry.py
"""Format handler registry."""

from pathlib import Path

from malscan_worker.extractors.base import FormatHandler


class HandlerRegistry:
    """Registry of format handlers, checked in registration order."""

    def __init__(self) -> None:
        self._handlers: list[FormatHandler] = []

    def register(self, handler: FormatHandler) -> None:
        self._handlers.append(handler)

    def detect(self, file_path: Path, mime: str) -> FormatHandler | None:
        """Return the first handler that can handle the file, or None."""
        magic = b""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(16)
        except OSError:
            pass
        for handler in self._handlers:
            if handler.can_handle(Path(file_path), mime, magic):
                return handler
        return None


def get_default_registry() -> HandlerRegistry:
    """Create a registry with all built-in handlers."""
    from malscan_worker.extractors.bz2_handler import Bz2Handler
    from malscan_worker.extractors.gzip_handler import GzipHandler
    from malscan_worker.extractors.iso_handler import IsoHandler
    from malscan_worker.extractors.rar_handler import RarHandler
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler
    from malscan_worker.extractors.tar_handler import TarHandler
    from malscan_worker.extractors.zip_handler import ZipHandler

    registry = HandlerRegistry()
    registry.register(ZipHandler())
    registry.register(SevenZipHandler())
    registry.register(RarHandler())
    registry.register(TarHandler())
    registry.register(GzipHandler())
    registry.register(Bz2Handler())
    registry.register(IsoHandler())
    return registry
