from typing import Dict, List
from enum import Enum
from datetime import datetime

class Industry(Enum):
    FINANCE = "finance"
    ECOMMERCE = "ecommerce"
    HEALTHCARE = "healthcare"

class ThreatPredictor:
    def predict_emerging_threats(self, industry: Industry, tech_stack: List[str]) -> Dict:
        threats = {
            "finance": ["API_ABUSE", "CREDENTIAL_STUFFING"],
            "ecommerce": ["CARDING", "INVENTORY_SCALPING"],
            "healthcare": ["DATA_EXFILTRATION", "RANSOMWARE"]
        }

        return {
            "predicted_threats": [
                {
                    "threat_type": threat,
                    "confidence": 0.85,
                    "impact": "HIGH",
                    "timeline": "1-3 months"
                }
                for threat in threats.get(industry.value, [])
            ],
            "risk_score": 75,
            "generated_at": datetime.now().isoformat()
        }
