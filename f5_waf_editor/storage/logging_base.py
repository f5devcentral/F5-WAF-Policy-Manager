"""
Abstract Base Class for F5 WAF Logging Profile Storage backends.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union


class LoggingProfileStorage(ABC):
    """Abstract interface for storing and managing F5 WAF Logging Profiles."""

    @abstractmethod
    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all logging profiles with metadata summary."""
        pass

    @abstractmethod
    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve parsed logging profile JSON."""
        pass

    @abstractmethod
    def get_raw_profile(self, name: str) -> Optional[str]:
        """Retrieve raw formatted JSON string."""
        pass

    @abstractmethod
    def save_profile(self, name: str, content: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Save or update a logging profile document."""
        pass

    @abstractmethod
    def delete_profile(self, name: str) -> bool:
        """Delete a logging profile."""
        pass

    @abstractmethod
    def clone_profile(self, source_name: str, new_name: str) -> Dict[str, Any]:
        """Clone an existing logging profile under a new name."""
        pass

    @abstractmethod
    def profile_exists(self, name: str) -> bool:
        """Check if a logging profile exists."""
        pass
