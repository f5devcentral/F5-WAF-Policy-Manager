"""
Abstract base class for User-Defined Signatures storage.
Supports both Redis and In-Memory implementations.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union


class CustomSignaturesStorage(ABC):
    """Abstract storage interface for User-Defined Signatures definition files."""

    @abstractmethod
    def list_signature_files(self) -> List[Dict[str, Any]]:
        """List summary metadata for all custom signature definition files."""
        raise NotImplementedError

    @abstractmethod
    def get_signature_file(self, tag: str) -> Optional[Dict[str, Any]]:
        """Retrieve the parsed JSON definition file for a given tag."""
        raise NotImplementedError

    @abstractmethod
    def get_raw_signature_file(self, tag: str) -> Optional[str]:
        """Retrieve the raw JSON string for a given tag."""
        raise NotImplementedError

    @abstractmethod
    def save_signature_file(self, tag: str, content: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Validate and persist a custom signatures definition file."""
        raise NotImplementedError

    @abstractmethod
    def delete_signature_file(self, tag: str) -> bool:
        """Delete the custom signatures definition file for a given tag."""
        raise NotImplementedError

    @abstractmethod
    def get_all_signatures(self) -> List[Dict[str, Any]]:
        """Retrieve flattened list of all signatures across all files with tag attribute attached."""
        raise NotImplementedError
