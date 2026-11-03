"""Extraction engine: decompilation, manifest parsing, code slicing, IoC extraction."""

from malintx.extraction.decompiler import DecompilerWrapper
from malintx.extraction.ioc import IoCExtractor
from malintx.extraction.manifest import ManifestParser
from malintx.extraction.slicer import CodeSlicer

__all__ = [
    "DecompilerWrapper",
    "IoCExtractor",
    "ManifestParser",
    "CodeSlicer",
]
