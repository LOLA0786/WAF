import random
import time
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

class AttackType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    XXE = "xml_external_entity"
    SSRF = "server_side_request_forgery"

@dataclass
class AttackResult:
    attack_type: AttackType
    payload: str
    blocked: bool
    processing_time_ms: float
    rule_triggered: Optional[str]

class EnterpriseAttackSimulator:
    def __init__(self):
        self.attack_payloads = {
            AttackType.SQL_INJECTION: [
                "' OR '1'='1' --",
                "'; DROP TABLE users; --",
                "UNION SELECT username, password FROM users",
                "' AND 1=1 --",
                "'; EXEC xp_cmdshell('dir') --"
            ],
            AttackType.XSS: [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert('XSS')",
                "<svg onload=alert(1)>",
                "<body onload=alert('XSS')>"
            ],
            AttackType.PATH_TRAVERSAL: [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../../etc/shadow",
                "....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            AttackType.COMMAND_INJECTION: [
                "; cat /etc/passwd",
                "| whoami",
                "&& net user",
                "$(cat /etc/passwd)",
                "'; system('id'); '"
            ]
        }
    
    def run_comprehensive_simulation(self, ruleset: List[Dict], duration_minutes: int = 5) -> Dict:
        """Run comprehensive attack simulation"""
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        results = []
        attack_count = 0
        blocked_count = 0
        
        while datetime.now() < end_time:
            # Generate random attack
            attack_type = random.choice(list(AttackType))
            payload = random.choice(self.attack_payloads[attack_type])
            
            # Test against ruleset
            blocked, processing_time, rule_triggered = self._test_attack(payload, ruleset)
            
            result = AttackResult(
                attack_type=attack_type,
                payload=payload,
                blocked=blocked,
                processing_time_ms=processing_time,
                rule_triggered=rule_triggered
            )
            
            results.append(result)
            attack_count += 1
            if blocked:
                blocked_count += 1
            
            # Small delay to simulate real traffic
            time.sleep(0.01)
        
        return self._generate_simulation_report(results, attack_count, blocked_count)
    
    def _test_attack(self, payload: str, ruleset: List[Dict]) -> Tuple[bool, float, Optional[str]]:
        """Test a single attack against ruleset"""
        start_time = time.time()
        
        for rule in ruleset:
            pattern = rule.get("pattern", "")
            rule_id = rule.get("id", "unknown")
            try:
                if re.search(pattern, payload, re.IGNORECASE):
                    processing_time = (time.time() - start_time) * 1000
                    return True, processing_time, rule_id
            except:
                continue
        
        processing_time = (time.time() - start_time) * 1000
        return False, processing_time, None
    
    def _generate_simulation_report(self, results: List[AttackResult], total_attacks: int, blocked_attacks: int) -> Dict:
        """Generate comprehensive simulation report"""
        
        # Calculate statistics by attack type
        attack_stats = {}
        for attack_type in AttackType:
            type_results = [r for r in results if r.attack_type == attack_type]
            if type_results:
                blocked = len([r for r in type_results if r.blocked])
                attack_stats[attack_type.value] = {
                    "total": len(type_results),
                    "blocked": blocked,
                    "block_rate": (blocked / len(type_results)) * 100,
                    "avg_processing_time": statistics.mean([r.processing_time_ms for r in type_results])
                }
        
        # Overall statistics
        overall_block_rate = (blocked_attacks / total_attacks) * 100
        avg_processing_time = statistics.mean([r.processing_time_ms for r in results])
        
        # Identify vulnerabilities
        vulnerabilities = []
        for attack_type, stats in attack_stats.items():
            if stats["block_rate"] < 80:  # Less than 80% block rate
                vulnerabilities.append({
                    "type": attack_type,
                    "block_rate": stats["block_rate"],
                    "risk_level": "HIGH" if stats["block_rate"] < 50 else "MEDIUM"
                })
        
        return {
            "simulation_summary": {
                "total_attacks": total_attacks,
                "blocked_attacks": blocked_attacks,
                "overall_block_rate": round(overall_block_rate, 2),
                "average_processing_time_ms": round(avg_processing_time, 2),
                "simulation_duration": "5 minutes",
                "vulnerabilities_found": len(vulnerabilities)
            },
            "attack_type_statistics": attack_stats,
            "identified_vulnerabilities": vulnerabilities,
            "performance_metrics": {
                "throughput_attacks_per_second": round(total_attacks / 300, 2),  # 5 minutes = 300 seconds
                "max_processing_time_ms": max([r.processing_time_ms for r in results]),
                "min_processing_time_ms": min([r.processing_time_ms for r in results])
            },
            "recommendations": self._generate_recommendations(vulnerabilities, overall_block_rate)
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict], overall_block_rate: float) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if overall_block_rate < 90:
            recommendations.append("Consider enhancing rule coverage for better protection")
        
        for vuln in vulnerabilities:
            if vuln["risk_level"] == "HIGH":
                recommendations.append(f"Immediate attention needed for {vuln['type']} protection (block rate: {vuln['block_rate']}%)")
            else:
                recommendations.append(f"Improve {vuln['type']} detection rules")
        
        if not recommendations:
            recommendations.append("Current ruleset provides excellent protection")
        
        return recommendations
    
    def zero_day_simulation(self, ruleset: List[Dict]) -> Dict:
        """Simulate zero-day and novel attacks"""
        # Generate novel attack vectors through mutation
        novel_attacks = self._generate_novel_attack_vectors()
        
        test_results = []
        for attack in novel_attacks:
            blocked, processing_time, rule_triggered = self._test_attack(attack, ruleset)
            test_results.append({
                "attack_vector": attack,
                "blocked": blocked,
                "processing_time_ms": processing_time,
                "rule_triggered": rule_triggered
            })
        
        unblocked_attacks = [r for r in test_results if not r["blocked"]]
        
        return {
            "novel_attacks_tested": len(test_results),
            "unblocked_attacks": len(unblocked_attacks),
            "zero_day_protection_score": 100 - (len(unblocked_attacks) / len(test_results) * 100),
            "critical_vulnerabilities": unblocked_attacks[:5],  # Top 5 unblocked
            "recommendations": [
                "Implement behavioral analysis rules",
                "Add machine learning-based detection",
                "Consider WAF with advanced threat intelligence"
            ] if unblocked_attacks else ["Excellent zero-day protection"]
        }
    
    def _generate_novel_attack_vectors(self) -> List[str]:
        """Generate novel attack vectors through mutation and obfuscation"""
        base_vectors = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "; ls -la",
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
        ]
        
        mutations = [
            lambda x: x.upper(),
            lambda x: x.lower(),
            lambda x: x.replace(" ", "/**/"),
            lambda x: x.replace("'", "%27"),
            lambda x: x.replace("<", "%3C"),
            lambda x: x.replace(">", "%3E"),
            lambda x: x.encode('unicode_escape').decode(),
            lambda x: ''.join([f"%{ord(c):02x}" for c in x]),
        ]
        
        novel_vectors = []
        for vector in base_vectors:
            for mutation in random.sample(mutations, 3):
                novel_vectors.append(mutation(vector))
        
        return list(set(novel_vectors))  # Remove duplicates
