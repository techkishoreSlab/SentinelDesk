"""Server-side package inspection (pkg, zip-with-app, dmg-with-app or dmg-with-pkg)."""

from app.catalogue.inspect.result import InspectError, Inspection
from app.catalogue.inspect.sandbox import inspect_sandboxed

__all__ = ["InspectError", "Inspection", "inspect_sandboxed"]
