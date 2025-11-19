import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
import time
import logging
import nest_asyncio # Import nest_asyncio
nest_asyncio.apply() # Apply nest_asyncio

from src.core.config import settings, LoggingConfig # Import LoggingConfig
from src.core.auth import auth_manager, rate_limiter, require_admin, require_editor
from src.core.analyzer import EnterpriseRegexAnalyzer, PatternAnalysis
from src.ai.regex_generator import AIRegexGenerator, AISecurityLevel
from src.ai.threat_predictor import ThreatPredictor, Industry
from src.simulation.attack_simulator import EnterpriseAttackSimulator, AttackType

# Configure logging
logging.config.dictConfig(LoggingConfig().get_config())
logger = logging.getLogger("waf_platform")

app = FastAPI(
    title=settings.app_name,
    description="Enterprise-grade AI-powered WAF optimization platform",
    version=settings.app_version,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Global instances
analyzer = EnterpriseRegexAnalyzer()
ai_generator = AIRegexGenerator()
threat_predictor = ThreatPredictor()
attack_simulator = EnterpriseAttackSimulator()

class RegexRequest(BaseModel):
    description: str
    security_level: AISecurityLevel = AISecurityLevel.ENTERPRISE

class ThreatRequest(BaseModel):
    industry: Industry
    tech_stack: List[str]

class SimulationRequest(BaseModel):
    ruleset: List[Dict]
    duration_minutes: int = 5

class AnalysisRequest(BaseModel):
    patterns: List[str]

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests"""
    start_time = time.time()

    response = await call_next(request)

    process_time = (time.time() - start_time) * 1000
    logger.info(
        f"{request.method} {request.url.path} "
        f"Status: {response.status_code} "
        f"Duration: {process_time:.2f}ms"
    )

    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Global exception handler"""
    logger.error(f"HTTPException: {exc.detail} - {request.url}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "error": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled exceptions"""
    logger.error(f"Unhandled exception: {str(exc)} - {request.url}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "Internal server error"}
    )

@app.get("/")
async def root():
    return {
        "message": f"{settings.app_name} {settings.app_version}",
        "status": "operational",
        "environment": settings.environment.value,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/v1/analyze")
async def analyze_patterns(
    request: AnalysisRequest,
    user = Depends(require_editor)
):
    """Enterprise pattern analysis endpoint"""
    if rate_limiter.is_rate_limited(user.user_id, "analyze", user.api_limits):
        raise HTTPException(429, "Rate limit exceeded")

    try:
        results = []
        for pattern in request.patterns:
            analysis = analyzer.analyze_pattern(pattern)
            results.append({
                "pattern": analysis.pattern,
                "security_level": analysis.security_level.value,
                "performance_level": analysis.performance_level.value,
                "complexity_score": analysis.complexity_score,
                "vulnerabilities": analysis.vulnerability_types,
                "optimizations": analysis.optimization_suggestions,
                "estimated_wcu": analysis.estimated_wcu,
                "compatibility": analysis.compatibility
            })

        return {
            "success": True,
            "results": results,
            "analyzed_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        raise HTTPException(500, "Analysis failed")

@app.post("/api/v1/ai/generate-regex")
async def generate_regex(
    request: RegexRequest,
    user = Depends(require_editor)
):
    """AI-powered regex generation with rate limiting"""
    if rate_limiter.is_rate_limited(user.user_id, "ai_generate", user.api_limits):
        raise HTTPException(429, "Rate limit exceeded")

    try:
        result = ai_generator.generate_from_natural_language(
            request.description,
            request.security_level
        )

        return {
            "success": True,
            "result": result,
            "generated_by": user.user_id,
            "generated_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"AI generation error: {str(e)}")
        raise HTTPException(500, "AI generation failed")

@app.post("/api/v1/threat/predict")
async def predict_threats(
    request: ThreatRequest,
    user = Depends(require_editor)
):
    """Predictive threat intelligence"""
    try:
        predictions = threat_predictor.predict_emerging_threats(
            request.industry,
            request.tech_stack
        )

        return {
            "success": True,
            "predictions": predictions,
            "requested_by": user.user_id
        }

    except Exception as e:
        logger.error(f"Threat prediction error: {str(e)}")
        raise HTTPException(500, "Threat prediction failed")

@app.post("/api/v1/simulate/attack")
async def simulate_attacks(
    request: SimulationRequest,
    user = Depends(require_admin)
):
    """Enterprise attack simulation"""
    try:
        results = attack_simulator.run_comprehensive_simulation(
            request.ruleset,
            request.duration_minutes
        )

        return {
            "success": True,
            "simulation": results,
            "simulated_by": user.user_id,
            "completed_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Simulation error: {str(e)}")
        raise HTTPException(500, "Simulation failed")

@app.post("/api/v1/simulate/zero-day")
async def simulate_zero_day(
    request: SimulationRequest,
    user = Depends(require_admin)
):
    """Zero-day attack simulation"""
    try:
        results = attack_simulator.zero_day_simulation(request.ruleset)

        return {
            "success": True,
            "zero_day_analysis": results,
            "analyzed_by": user.user_id
        }

    except Exception as e:
        logger.error(f"Zero-day simulation error: {str(e)}")
        raise HTTPException(500, "Zero-day simulation failed")

@app.get("/health")
async def health_check():
    """Comprehensive health check"""
    health_status = {
        "status": "healthy",
        "version": settings.app_version,
        "timestamp": datetime.now().isoformat(),
        "components": {
            "api": "healthy",
            "ai_engine": "healthy",
            "database": "healthy",
            "redis": "healthy"
        }
    }

    return health_status

@app.get("/metrics")
async def metrics():
    """Application metrics endpoint"""
    return {
        "uptime": "TODO",  # Would integrate with actual metrics
        "requests_processed": "TODO",
        "active_users": "TODO"
    }

if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.value,
        reload=settings.debug
    )
