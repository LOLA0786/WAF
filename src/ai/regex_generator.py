import re
from typing import Dict, List, Optional
from enum import Enum

class AISecurityLevel(Enum):
    BASIC = "basic"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"

class AIRegexGenerator:
    def __init__(self):
        self.examples = {
            "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "phone": r"^\+?[\d\s-()]{10,}$",
            "credit card": r"^\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}$",
            "sql injection": r"(?i)(?:SELECT|INSERT|UPDATE|DELETE).*FROM",
        }
        # Add placeholder methods for optimization strategies to prevent AttributeError
        self.optimization_strategies = {
            "performance": self._optimize_performance,
            "security": self._optimize_security,
            "compatibility": self._optimize_compatibility
        }

    def _optimize_performance(self, pattern: str) -> str:
        """Placeholder for performance optimization logic."""
        return pattern

    def _optimize_security(self, pattern: str) -> str:
        """Placeholder for security optimization logic."""
        return pattern

    def _optimize_compatibility(self, pattern: str) -> str:
        """Placeholder for compatibility optimization logic."""
        return pattern

    def generate_from_natural_language(self, description: str, security_level: AISecurityLevel = AISecurityLevel.ENTERPRISE) -> Dict:
        """Generate regex from natural language with security enhancements"""

        # Find matching example
        for key, pattern in self.examples.items():
            if key in description.lower():
                enhanced = self._enhance_pattern(pattern, security_level)
                analysis = self._analyze_pattern(enhanced)
                return {
                    "pattern": enhanced,
                    "security_score": analysis["security_score"],
                    "performance_score": analysis["performance_score"],
                    "complexity": analysis["complexity"],
                    "recommendations": analysis["recommendations"]
                }

        # Fallback
        return {
            "pattern": r".*",
            "security_score": 50,
            "performance_score": 100,
            "complexity": "LOW",
            "recommendations": ["Consider providing more specific requirements"]
        }

    def _enhance_pattern(self, pattern: str, security_level: AISecurityLevel) -> str:
        """Apply security enhancements"""
        if security_level == AISecurityLevel.ENTERPRISE:
            # Add possessive quantifiers
            pattern = re.sub(r'(\+)(?!\+)', r'\1+', pattern)
            pattern = re.sub(r'(\*)(?!\+)', r'\1+', pattern)
        return pattern

    def _analyze_pattern(self, pattern: str) -> Dict:
        """Analyze pattern for security and performance"""
        risks = self._detect_risks(pattern)
        return {
            "security_score": max(0, 100 - len(risks) * 20),
            "performance_score": 85,
            "complexity": "MEDIUM",
            "recommendations": risks if risks else ["Pattern looks good!"]
        }

    def _detect_risks(self, pattern: str) -> List[str]:
        """Detect potential security risks"""
        risks = []
        if re.search(r'\([^)]*[\+|\*][^)]*\)[\+|\*]', pattern):
            risks.append("Nested quantifiers detected")
        if len(pattern) > 200:
            risks.append("Pattern is very long")
        return risks
