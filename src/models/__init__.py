"""Data storage models and database access for SecuDoc."""
from .database import DatabaseManager, get_db

__all__ = ["DatabaseManager", "get_db"]
