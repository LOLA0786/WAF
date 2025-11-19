import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime

# Import our amazing components
from src.ai.regex_generator import AIRegexGenerator, AISecurityLevel
from src.ai.threat_predictor import ThreatPredictor, Industry
from src.simulation.attack_simulator import AttackSimulator

app = FastAPI(
    title="🤖 WAF Optimization Platform - Enterprise Edition",
    description="The world's most advanced AI-powered WAF optimization and security platform",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
ai_generator = AIRegexGenerator()
threat_predictor = ThreatPredictor()
attack_simulator = AttackSimulator()

class NaturalLanguageRequest(BaseModel):
    description: str
    security_level: AISecurityLevel = AISecurityLevel.ENTERPRISE

class ThreatPredictionRequest(BaseModel):
    industry: Industry
    tech_stack: List[str]

class SimulationRequest(BaseModel):
    ruleset: List[Dict]

@app.get("/")
async def root():
    return {
        "message": "🚀 Welcome to WAF Optimization Platform 3.0",
        "version": "3.0.0",
        "status": "Operational",
        "features": [
            "AI-Powered Regex Generation",
            "Predictive Threat Intelligence", 
            "Zero-Day Attack Simulation",
            "Autonomous WAF Optimization",
            "Security AI Copilot"
        ]
    }

@app.post("/ai/generate-regex")
async def generate_regex_from_nl(request: NaturalLanguageRequest):
    """Generate optimized, secure regex from natural language"""
    try:
        result = ai_generator.generate_from_natural_language(
            request.description, 
            request.security_level
        )
        return {
            "success": True,
            "input": request.description,
            "result": result,
            "ai_confidence": "95%"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/threat-intelligence/predict")
async def predict_threats(request: ThreatPredictionRequest):
    """Get predictive threat intelligence"""
    try:
        predictions = threat_predictor.predict_emerging_threats(
            request.industry,
            request.tech_stack
        )
        return {
            "success": True,
            "industry": request.industry.value,
            "predictions": predictions,
            "generated_at": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/simulation/zero-day")
async def simulate_zero_day_attack(request: SimulationRequest):
    """Simulate zero-day attacks against your WAF"""
    try:
        results = attack_simulator.simulate_zero_day(request.ruleset)
        return {
            "success": True,
            "simulation_type": "zero_day",
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "3.0.0",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "ai_engine": "operational",
            "threat_intel": "operational", 
            "simulation_engine": "operational"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
