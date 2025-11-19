import re
import dataclasses
from enum import Enum
from typing import Dict, List, Optional, Tuple

class RegexEngine(Enum):
    PCRE = "pcre"
    RE2 = "re2"
    PYTHON = "python"
    JAVASCRIPT = "javascript"

class ComplexityLevel(Enum):
    LINEAR = "O(n)"
    POLYNOMIAL = "O(n^2)"
    EXPONENTIAL = "O(2^n)"

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclasses.dataclass
class RegexAnalysis:
    pattern: str
    is_vulnerable: bool
    complexity: ComplexityLevel
    vulnerability_type: Optional[str]
    suggested_fix: Optional[str]
    compatibility: Dict[RegexEngine, bool]
    performance_score: float
    security_level: SecurityLevel
    explanation: str

class ProductionRegexAnalyzer:
    def __init__(self):
        self.redos_patterns = [
            (r'\([^)]*\+\)\+', "nested_quantifiers", SecurityLevel.CRITICAL),
            (r'\([^)]*\*\)\*', "nested_quantifiers", SecurityLevel.CRITICAL),
            (r'\([^)]*\)\\{[^}]*,\\}[^}]*\\?', "exponential_quantifiers", SecurityLevel.HIGH),
        ]
    
    def analyze_pattern(self, pattern: str) -> RegexAnalysis:
        """Production-grade regex pattern analysis"""
        is_vulnerable, vuln_type, security_level = self._check_redos_vulnerability(pattern)
        complexity = self._calculate_complexity(pattern)
        compatibility = self._check_compatibility(pattern)
        explanation = self._generate_explanation(pattern, is_vulnerable, vuln_type, complexity)
        
        return RegexAnalysis(
            pattern=pattern,
            is_vulnerable=is_vulnerable,
            complexity=complexity,
            vulnerability_type=vuln_type,
            suggested_fix=self._suggest_fix(pattern, vuln_type) if is_vulnerable else None,
            compatibility=compatibility,
            performance_score=self._calculate_performance_score(pattern, complexity),
            security_level=security_level,
            explanation=explanation
        )
    
    def _check_redos_vulnerability(self, pattern: str) -> Tuple[bool, Optional[str], SecurityLevel]:
        for redos_pattern, vuln_type, security_level in self.redos_patterns:
            if re.search(redos_pattern, pattern):
                return True, vuln_type, security_level
        return False, None, SecurityLevel.LOW
    
    def _calculate_complexity(self, pattern: str) -> ComplexityLevel:
        if re.search(r'\([^)]*[\+|\*][^)]*\)[\+|\*]', pattern):
            return ComplexityLevel.EXPONENTIAL
        elif len(re.findall(r'[\+|\*|\?]', pattern)) > 2:
            return ComplexityLevel.POLYNOMIAL
        else:
            return ComplexityLevel.LINEAR
    
    def _check_compatibility(self, pattern: str) -> Dict[RegexEngine, bool]:
        compatibility = {}
        for engine in RegexEngine:
            try:
                re.compile(pattern)
                compatibility[engine] = True
            except re.error:
                compatibility[engine] = False
        return compatibility
    
    def _suggest_fix(self, pattern: str, vulnerability_type: str) -> str:
        from .autofix import EnhancedAutoFixRewriter
        fixer = EnhancedAutoFixRewriter()
        result = fixer.generate_fix(pattern, vulnerability_type)
        return result.get("fixed_pattern", pattern)
    
    def _calculate_performance_score(self, pattern: str, complexity: ComplexityLevel) -> float:
        base_score = 100
        complexity_penalty = {
            ComplexityLevel.LINEAR: 0,
            ComplexityLevel.POLYNOMIAL: 30,
            ComplexityLevel.EXPONENTIAL: 60
        }
        score = base_score - complexity_penalty.get(complexity, 0)
        return max(10, min(100, score))
    
    def _generate_explanation(self, pattern: str, is_vulnerable: bool, 
                            vuln_type: Optional[str], complexity: ComplexityLevel) -> str:
        if not is_vulnerable:
            return "This pattern appears safe from ReDoS attacks."
        
        explanations = {
            "nested_quantifiers": "Nested quantifiers can cause exponential backtracking.",
            "exponential_quantifiers": "Open-ended quantifiers can cause exponential performance issues.",
        }
        return explanations.get(vuln_type, "This pattern may be vulnerable to ReDoS attacks.")
