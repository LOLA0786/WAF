import pytest
from src.core.analyzer import ProductionRegexAnalyzer

def test_redos_detection():
    analyzer = ProductionRegexAnalyzer()
    
    # Test vulnerable patterns
    result = analyzer.analyze_pattern("(a+)+")
    assert result.is_vulnerable == True
    
    # Test safe patterns  
    result = analyzer.analyze_pattern("simple")
    assert result.is_vulnerable == False

def test_complexity_calculation():
    analyzer = ProductionRegexAnalyzer()
    
    result = analyzer.analyze_pattern("(a+)+")
    assert "EXPONENTIAL" in result.complexity.value
    
    result = analyzer.analyze_pattern("simple")
    assert "LINEAR" in result.complexity.value
