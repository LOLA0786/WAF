from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict
import dataclasses

from ..core.analyzer import ProductionRegexAnalyzer, RegexAnalysis
from ..core.autofix import EnhancedAutoFixRewriter

router = APIRouter()

# Initialize components
production_analyzer = ProductionRegexAnalyzer()
enhanced_fixer = EnhancedAutoFixRewriter()

class ScanRequest(BaseModel):
    patterns: List[str]

class OptimizationRequest(BaseModel):
    pattern: str
    vulnerability_type: str

@router.post("/scan/patterns")
async def scan_patterns(request: ScanRequest):
    """Scan regex patterns for vulnerabilities"""
    results = []
    for pattern in request.patterns:
        analysis = production_analyzer.analyze_pattern(pattern)
        results.append(dataclasses.asdict(analysis))
    
    return {
        "total_patterns": len(results),
        "vulnerable_patterns": len([r for r in results if r['is_vulnerable']]),
        "results": results
    }

@router.post("/optimize/fix")
async def optimize_pattern(request: OptimizationRequest):
    """Generate optimized version of vulnerable pattern"""
    return enhanced_fixer.generate_fix(request.pattern, request.vulnerability_type)

@router.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "version": "2.0.0",
        "features": ["ReDoS detection", "Performance scoring", "Security assessment"]
    }
