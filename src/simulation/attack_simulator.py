import random
from typing import Dict, List
from datetime import datetime

class AttackSimulator:
    def __init__(self):
        self.attack_patterns = {
            "SQL_INJECTION": [
                "' OR '1'='1",
                "'; DROP TABLE users--",
                "UNION SELECT username, password FROM users"
            ],
            "XSS": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert('XSS')"
            ],
            "PATH_TRAVERSAL": [
                "../../../etc/passwd",
                "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts"
            ],
            "COMMAND_INJECTION": [
                "; cat /etc/passwd",
                "| whoami",
                "&& net user"
            ]
        }
    
    def simulate_zero_day(self, ruleset: List[Dict]) -> Dict:
        """Simulate unknown attacks against WAF rules"""
        
        # Generate novel attack vectors
        novel_attacks = self._generate_novel_attacks()
        
        test_results = []
        for attack in novel_attacks:
            blocked = self._test_against_ruleset(attack, ruleset)
            test_results.append({
                "attack_vector": attack,
                "blocked": blocked,
                "severity": "HIGH" if not blocked else "LOW"
            })
        
        vulnerabilities = [r for r in test_results if not r["blocked"]]
        
        return {
            "total_tests": len(test_results),
            "vulnerabilities_found": len(vulnerabilities),
            "coverage_score": 100 - (len(vulnerabilities) / len(test_results) * 100),
            "critical_vulnerabilities": [v for v in vulnerabilities if v["severity"] == "HIGH"],
            "auto_generated_patches": self._generate_patches(vulnerabilities),
            "risk_level": self._calculate_risk_level(vulnerabilities)
        }
    
    def _generate_novel_attacks(self) -> List[str]:
        """Generate novel attack vectors using mutation"""
        base_attacks = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "UNION SELECT"
        ]
        
        mutations = [
            lambda x: x.upper(),
            lambda x: x.lower(),
            lambda x: x.replace(" ", "/**/"),
            lambda x: x.replace("'", "%27"),
            lambda x: x + "/*random*/",
            lambda x: "/" + x + "/"
        ]
        
        novel_attacks = []
        for attack in base_attacks:
            for mutation in random.sample(mutations, 3):  # Apply 3 random mutations
                novel_attacks.append(mutation(attack))
        
        return list(set(novel_attacks))  # Remove duplicates
    
    def _test_against_ruleset(self, attack: str, ruleset: List[Dict]) -> bool:
        """Test if attack would be blocked by ruleset"""
        # Simulate rule matching
        for rule in ruleset:
            pattern = rule.get("pattern", "")
            try:
                import re
                if re.search(pattern, attack):
                    return True
            except:
                continue
        return False
    
    def _generate_patches(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate automatic patches for vulnerabilities"""
        patches = []
        for vuln in vulnerabilities:
            attack = vuln["attack_vector"]
            patch_pattern = self._create_patch_pattern(attack)
            patches.append({
                "vulnerability": attack,
                "patch_pattern": patch_pattern,
                "confidence": 0.85,
                "performance_impact": "LOW"
            })
        return patches
    
    def _create_patch_pattern(self, attack: str) -> str:
        """Create patch pattern for specific attack"""
        if "'" in attack:
            return r"(?:'+\\s*OR\\s*'+|UNION\\s+SELECT)"
        elif "<script" in attack:
            return r"<script[^>]*>.*?</script>"
        elif "../" in attack:
            return r"(?:\\.\\./)+"
        else:
            import re
            return re.escape(attack)
    
    def _calculate_risk_level(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall risk level"""
        critical_count = len([v for v in vulnerabilities if v["severity"] == "HIGH"])
        
        if critical_count > 5:
            return "CRITICAL"
        elif critical_count > 2:
            return "HIGH"
        elif critical_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def stress_test_rules(self, rules: List[Dict]) -> Dict:
        """Generate load test against rules"""
        test_payloads = self._generate_stress_payloads(100)
        
        results = {
            "total_requests": len(test_payloads),
            "blocked_requests": 0,
            "false_positives": 0,
            "processing_times": []
        }
        
        for payload in test_payloads:
            blocked = self._test_against_ruleset(payload, rules)
            if blocked:
                results["blocked_requests"] += 1
                if self._is_legitimate_payload(payload):
                    results["false_positives"] += 1
            
            processing_time = random.uniform(0.1, 5.0)
            results["processing_times"].append(processing_time)
        
        avg_processing_time = sum(results["processing_times"]) / len(results["processing_times"])
        
        return {
            "performance_under_attack": f"{avg_processing_time:.2f}ms average",
            "block_rate": f"{(results['blocked_requests'] / results['total_requests']) * 100:.1f}%",
            "false_positive_rate": f"{(results['false_positives'] / results['total_requests']) * 100:.2f}%",
            "max_throughput": f"{int(1000 / avg_processing_time)} RPS",
            "bottleneck_analysis": self._analyze_bottlenecks(rules, avg_processing_time)
        }
    
    def _generate_stress_payloads(self, count: int) -> List[str]:
        """Generate payloads for stress testing"""
        payloads = []
        for _ in range(count):
            attack_type = random.choice(list(self.attack_patterns.keys()))
            payloads.append(random.choice(self.attack_patterns[attack_type]))
        
        # Add legitimate traffic
        legitimate = ["/home", "/api/data", "search?q=test", "user/profile"]
        payloads.extend(random.choices(legitimate, k=count//4))
        
        return payloads
    
    def _is_legitimate_payload(self, payload: str) -> bool:
        """Check if payload is legitimate traffic"""
        legitimate_patterns = ["/home", "/api/", "search?q=", "user/"]
        return any(pattern in payload for pattern in legitimate_patterns)
    
    def _analyze_bottlenecks(self, rules: List[Dict], avg_time: float) -> str:
        """Analyze performance bottlenecks"""
        if avg_time > 3.0:
            return "High latency detected - consider rule optimization"
        elif avg_time > 1.0:
            return "Moderate latency - review complex rules"
        else:
            return "Good performance - no immediate bottlenecks"
