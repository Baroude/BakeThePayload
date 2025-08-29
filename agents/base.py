# ABOUTME: Base agent class providing common functionality for all vulnerability analysis agents
# ABOUTME: Includes configuration management, logging, and shared utilities for agent implementations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseAgent(ABC):
    """Base class for all vulnerability analysis agents."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize base agent with configuration."""
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    async def process(self, data: Any) -> Any:
        """Process data according to agent's specific functionality."""
        pass

    async def initialize(self) -> None:
        """Initialize agent resources."""
        pass

    async def cleanup(self) -> None:
        """Clean up agent resources."""
        pass
