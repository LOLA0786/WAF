from typing import Dict, List
from datetime import datetime
from enum import Enum

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Industry(Enum):
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    ECOMMERCE = "ecommerce"
    TECHNOLOGY = "technology"
    GOVERNMENT = "government"

class ThreatPredictor:
    def __init__(self):
        self.threat_intelligence = {
            "finance": ["API_ABUSE", "CREDENTIAL_STUFFING", "BOT_ATTACKS"],
            "healthcare": ["DATA_EXFILTRATION", "RANSOMWARE", "PHI_THEFT"],
            "ecommerce": ["CARDING", "INVENTORY_SCALPING", "LOYALTY_FRAUD"],
            "technology": ["CODE_INJECTION", "SUPPLY_CHAIN", "ZERO_DAY"],
            "government": ["ESPIONAGE", "DDoS", "DATA_MANIPULATION"]
        }

    def predict_emerging_threats(self, industry: Industry, tech_stack: List[str]) -> Dict:
        """Predict upcoming threats based on industry and technology"""

        base_threats = self.threat_intelligence.get(industry.value, [])

        # Add tech-specific threats
        tech_threats = []
        if "react" in tech_stack:
            tech_threats.append("XSS_VIA_PROPS")
        if "nodejs" in tech_stack:
            tech_threats.append("PROTOTYPE_POLLUTION")
        if "python" in tech_stack:
            tech_threats.append("DESERIALIZATION_ATTACKS")
        if "aws" in tech_stack:
            tech_threats.append("CLOUD_MISCONFIGURATION")

        all_threats = base_threats + tech_threats

        return {
            "industry": industry.value,
            "predicted_threats": [
                {
                    "threat_type": threat,
                    "confidence": self._calculate_confidence(threat, industry),
                    "expected_impact": self._estimate_impact(threat),
                    "timeline": self._predict_timeline(threat),
                    "recommended_rules": self._generate_rule_recommendations(threat),
                    "mitigation_strategy": self._suggest_mitigation(threat)
                }
                for threat in all_threats[:5]  # Top 5 threats
            ],
            "risk_score": self._calculate_overall_risk(all_threats),
            "last_updated": datetime.now().isoformat()
        }

    def _calculate_confidence(self, threat: str, industry: Industry) -> float:
        """Calculate prediction confidence"""
        base_confidence = 0.7

        # Adjust based on threat characteristics
        if "ZERO_DAY" in threat:
            base_confidence -= 0.2
        if "DDoS" in threat:
            base_confidence += 0.1

        return max(0.3, min(0.95, base_confidence))

    def _estimate_impact(self, threat: str) -> str:
        """Estimate business impact"""
        high_impact = ["RANSOMWARE", "DATA_EXFILTRATION", "ZERO_DAY"]
        medium_impact = ["DDoS", "CREDENTIAL_STUFFING", "CARDING"]

        if threat in high_impact:
            return "HIGH"
        elif threat in medium_impact:
            return "MEDIUM"
        else:
            return "LOW"

    def _predict_timeline(self, threat: str) -> str:
        """Predict when threat might materialize"""
        if "ZERO_DAY" in threat:
            return "1-3 months"
        elif "SEASONAL" in threat:
            return "Next quarter"
        else:
            return "Imminent"

    def _generate_rule_recommendations(self, threat: str) -> List[str]:
        """Generate WAF rule recommendations for threat"""
        rule_mapping = {
            "API_ABUSE": ["rate_limiting", "behavioral_analysis", "bot_detection"],
            "CREDENTIAL_STUFFING": ["credential_stuffing_detection", "ip_reputation"],
            "XSS_VIA_PROPS": ["xss_protection", "input_validation"],
            "SQL_INJECTION": ["sql_injection_detection", "input_sanitization"]
        }

        return rule_mapping.get(threat, ["generic_protection"])

    def _suggest_mitigation(self, threat: str) -> str:
        """Suggest mitigation strategies"""
        mitigations = {
            "API_ABUSE": "Implement rate limiting and API gateway protection",
            "CREDENTIAL_STUFFING": "Deploy multi-factor authentication and CAPTCHA",
            "DDoS": "Use cloud-based DDoS protection service",
            "XSS_VIA_PROPS": "Implement Content Security Policy and input encoding"
        }

        return mitigations.get(threat, "Review and update security controls")

    def _calculate_overall_risk(self, threats: List[str]) -> int:
        """Calculate overall risk score (0-100)"""
        if not threats:
            return 0

        threat_weights = {
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1
        }

        total_weight = sum(threat_weights[self._estimate_impact(t)] for t in threats)
        max_possible = len(threats) * 3

        return int((total_weight / max_possible) * 100) if max_possible > 0 else 0
