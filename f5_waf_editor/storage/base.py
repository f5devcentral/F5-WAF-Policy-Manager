"""
Base abstract interface for F5 WAF Policy Storage.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class PolicyStorage(ABC):
    """Abstract interface defining operations for managing F5 WAF policies."""

    @abstractmethod
    def list_policies(self) -> List[Dict[str, Any]]:
        """List all policy summaries."""
        pass

    @abstractmethod
    def get_policy(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve a parsed policy JSON dict by name."""
        pass

    @abstractmethod
    def get_raw_policy(self, name: str) -> Optional[str]:
        """Retrieve raw policy JSON string by name."""
        pass

    @abstractmethod
    def save_policy(self, name: str, policy_content: Any, pre_validated: bool = False) -> Dict[str, Any]:
        """Save a policy JSON by name. policy_content can be dict or JSON string."""
        pass

    @abstractmethod
    def delete_policy(self, name: str) -> bool:
        """Delete a policy by name. Returns True if deleted, False if not found."""
        pass

    @abstractmethod
    def policy_exists(self, name: str) -> bool:
        """Check if a policy exists."""
        pass

    @abstractmethod
    def clone_policy(self, source_name: str, new_name: str) -> Dict[str, Any]:
        """Clone an existing policy under a new name."""
        pass

    @abstractmethod
    def rename_policy(self, old_name: str, new_name: str, policy_content: Optional[Any] = None) -> Dict[str, Any]:
        """Rename an existing policy from old_name to new_name, optionally updating its content."""
        pass

    @abstractmethod
    def get_health(self) -> Dict[str, Any]:
        """Get backend connectivity, status, and health metrics."""
        pass
