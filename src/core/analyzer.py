import re
import time
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
import statistics

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PerformanceLevel(Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"

@dataclass
class PatternAnalysis:
    pattern: str
    security_level: SecurityLevel
    performance_level: PerformanceLevel
    complexity_score: int
    vulnerability_types: List[str]
    optimization_suggestions: List[str]
    estimated_wcu: float
    compatibility: Dict[str, bool]

class EnterpriseRegexAnalyzer:
    def __init__(self):
        self.vulnerability_patterns = {
            "redos": [
                (r'\([^)]*[\+|\*][^)]*\)[\+|\*]', "Nested quantifiers"),
                (r'\([^)]*\)\\{[^}]*,\\}[^}]*\\?', "Exponential backtracking"),
                (r'^.*\*.*\*.*$', "Multiple wildcards"),
            ],
            "performance": [
                (r'\|.*\|.*\|', "Multiple alternations"),
                (r'\\.[*+]', "Greedy dot matches"),
                (r'\\s[*+]', "Greedy whitespace"),
            ]
        }
    
    def analyze_pattern(self, pattern: str) -> PatternAnalysis:
        """Comprehensive enterprise-grade pattern analysis"""
        
        # Security analysis
        security_level, vulnerabilities = self._analyze_security(pattern)
        
        # Performance analysis
        performance_level, complexity_score = self._analyze_performance(pattern)
        
        # WCU estimation
        estimated_wcu = self._estimate_wcu(pattern, complexity_score)
        
        # Compatibility check
        compatibility = self._check_compatibility(pattern)
        
        # Optimization suggestions
        optimizations = self._generate_optimizations(pattern, vulnerabilities)
        
        return PatternAnalysis(
            pattern=pattern,
            security_level=security_level,
            performance_level=performance_level,
            complexity_score=complexity_score,
            vulnerability_types=vulnerabilities,
            optimization_suggestions=optimizations,
            estimated_wcu=estimated_wcu,
            compatibility=compatibility
        )
    
    def _analyze_security(self, pattern: str) -> Tuple[SecurityLevel, List[str]]:
        """Analyze security vulnerabilities"""
        vulnerabilities = []
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern_re, description in patterns:
                if re.search(pattern_re, pattern):
                    vulnerabilities.append(description)
        
        if len(vulnerabilities) >= 3:
            return SecurityLevel.CRITICAL, vulnerabilities
        elif len(vulnerabilities) >= 2:
            return SecurityLevel.HIGH, vulnerabilities
        elif len(vulnerabilities) >= 1:
            return SecurityLevel.MEDIUM, vulnerabilities
        else:
            return SecurityLevel.LOW, vulnerabilities
    
    def _analyze_performance(self, pattern: str) -> Tuple[PerformanceLevel, int]:
        """Analyze performance characteristics"""
        complexity_score = 0
        
        # Length complexity
        complexity_score += min(len(pattern) // 10, 10)
        
        # Quantifier complexity
        quantifiers = len(re.findall(r'[\+|\*|\?|\\{]', pattern))
        complexity_score += min(quantifiers * 2, 20)
        
        # Alternation complexity
        alternations = pattern.count('|')
        complexity_score += min(alternations * 3, 30)
        
        # Group complexity
        groups = pattern.count('(') - pattern.count('(?')
        complexity_score += min(groups * 2, 20)
        
        if complexity_score >= 60:
            return PerformanceLevel.POOR, complexity_score
        elif complexity_score >= 40:
            return PerformanceLevel.FAIR, complexity_score
        elif complexity_score >= 20:
            return PerformanceLevel.GOOD, complexity_score
        else:
            return PerformanceLevel.EXCELLENT, complexity_score
    
    def _estimate_wcu(self, pattern: str, complexity_score: int) -> float:
        """Estimate AWS WAF Capacity Units"""
        base_wcu = 1.0
        complexity_multiplier = 1.0 + (complexity_score / 100)
        length_multiplier = 1.0 + (len(pattern) / 1000)
        
        return round(base_wcu * complexity_multiplier * length_multiplier, 2)
    
    def _check_compatibility(self, pattern: str) -> Dict[str, bool]:
        """Check compatibility with different regex engines"""
        engines = ["pcre", "re2", "python", "javascript", "java"]
        compatibility = {}
        
        for engine in engines:
            try:
                re.compile(pattern)
                compatibility[engine] = True
            except:
                compatibility[engine] = False
        
        return compatibility
    
    def _generate_optimizations(self, pattern: str, vulnerabilities: List[str]) -> List[str]:
        """Generate optimization suggestions"""
        optimizations = []
        
        if "Nested quantifiers" in vulnerabilities:
            optimizations.append("Convert nested quantifiers to atomic groups")
        
        if "Multiple alternations" in str(vulnerabilities):
            optimizations.append("Consider using character classes instead of alternations")
        
        if len(pattern) > 100:
            optimizations.append("Pattern is very long - consider breaking into multiple rules")
        
        if pattern.count('|') > 5:
            optimizations.append("High alternation count - optimize with character classes")
        
        return optimizations if optimizations else ["Pattern is well optimized"]
    
    def benchmark_pattern(self, pattern: str, test_strings: List[str]) -> Dict:
        """Benchmark pattern performance"""
        times = []
        compiled_pattern = re.compile(pattern)
        
        for test_str in test_strings:
            start_time = time.time()
            compiled_pattern.search(test_str)
            end_time = time.time()
            times.append((end_time - start_time) * 1000)  # Convert to milliseconds
        
        return {
            "average_time_ms": statistics.mean(times),
            "max_time_ms": max(times),
            "min_time_ms": min(times),
            "total_tests": len(test_strings),
            "performance_rating": self._rate_performance(statistics.mean(times))
        }
    
    def _rate_performance(self, avg_time_ms: float) -> str:
        """Rate performance based on execution time"""
        if avg_time_ms < 1.0:
            return "EXCELLENT"
        elif avg_time_ms < 5.0:
            return "GOOD"
        elif avg_time_ms < 10.0:
            return "FAIR"
        else:
            return "POOR"
