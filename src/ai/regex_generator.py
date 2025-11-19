import re
from typing import Dict, List, Optional
from enum import Enum

class AISecurityLevel(Enum):
    BASIC = "basic"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"

class AIRegexGenerator:
    def __init__(self):
        # Define these methods as placeholders to prevent AttributeError
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
        """Transform natural language into optimized, secure regex"""

        # Simulated AI response
        examples = {
            "email validation": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "credit card numbers": r"^\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}$",
            "sql injection detection": r"(?:\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\b(?:FROM|INTO|SET|WHERE)\b|\b(?:OR|AND)\b\s*\d+\s*=\s*\d+)",
        }

        for key, pattern in examples.items():
            if key in description.lower():
                return self._enhance_pattern(pattern, security_level)

        # Fallback pattern
        base_pattern = self._create_fallback_pattern(description)
        return self._enhance_pattern(base_pattern, security_level)

    def _enhance_pattern(self, pattern: str, security_level: AISecurityLevel) -> Dict:
        """Apply security and performance enhancements"""
        enhanced = pattern

        if security_level == AISecurityLevel.ENTERPRISE:
            enhanced = re.sub(r'(\+)(?!\+)', r'\1+', enhanced)
            enhanced = re.sub(r'(\*)(?!\+)', r'\1+', enhanced)
            # Fix for unbalanced parenthesis error and SyntaxWarning: use character classes for literal parentheses
            enhanced = re.sub(r'[\[]([^)]+\|[^)]+)[\]]', r'(?>\1)', enhanced)

        analysis = self._analyze_pattern(enhanced)

        return {
            "pattern": enhanced,
            "original_description": "AI-generated pattern",
            "security_score": analysis["security_score"],
            "performance_score": analysis["performance_score"],
            "complexity": analysis["complexity"],
            "recommendations": analysis["recommendations"]
        }

    def _analyze_pattern(self, pattern: str) -> Dict:
        """Comprehensive pattern analysis"""
        security_risks = self._detect_security_risks(pattern)
        performance_metrics = self._calculate_performance_metrics(pattern)

        return {
            "security_score": max(0, 100 - len(security_risks) * 10),
            "performance_score": performance_metrics["score"],
            "complexity": performance_metrics["complexity"],
            "security_risks": security_risks,
            "recommendations": self._generate_recommendations(security_risks, performance_metrics)
        }

    def _detect_security_risks(self, pattern: str) -> List[str]:
        """Detect potential security vulnerabilities"""
        risks = []

        if re.search(r'\([^)]*[\+|\*][^)]*\)[\+|\*]', pattern):
            risks.append("Nested quantifiers - potential ReDoS")

        if len(pattern) > 500:
            risks.append("Very long pattern - performance impact")

        if pattern.count('|') > 10:
            risks.append("Excessive alternation - performance degradation")

        return risks

    def _calculate_performance_metrics(self, pattern: str) -> Dict:
        """Calculate performance characteristics"""
        complexity_score = 0

        complexity_score += len(re.findall(r'[\+|\*|\?]', pattern)) * 2
        complexity_score += pattern.count('|') * 3
        complexity_score += pattern.count('(') * 1

        if complexity_score < 10:
            complexity = "LOW"
            performance_score = 95
        elif complexity_score < 25:
            complexity = "MEDIUM"
            performance_score = 75
        else:
            complexity = "HIGH"
            performance_score = 50

        return {
            "complexity": complexity,
            "score": performance_score,
            "complexity_score": complexity_score
        }

    def _generate_recommendations(self, risks: List[str], metrics: Dict) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []

        if risks:
            recommendations.append("Security risks detected - consider using atomic groups")

        if metrics["complexity"] == "HIGH":
            recommendations.append("High complexity pattern - consider simplification")

        if metrics["score"] < 70:
            recommendations.append("Performance optimization recommended")

        return recommendations if recommendations else ["Pattern looks good!"]

    def _create_fallback_pattern(self, description: str) -> str:
        """Create basic pattern from description"""
        words = description.lower().split()
        if "email" in words:
            return r"^\S+@\S+\.\S+$"
        elif "phone" in words:
            return r"^\+?[\d\s-()]+$"
        elif "url" in words:
            return r"^https?://[\w.-]+\.[a-z]{2,}"
        else:
            return r"^.*$"
