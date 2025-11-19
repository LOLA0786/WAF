import re
from typing import Dict, List

class EnhancedAutoFixRewriter:
    def generate_fix(self, pattern: str, vulnerability_type: str) -> Dict:
        fixed_pattern = pattern
        
        if vulnerability_type == "nested_quantifiers":
            fixed_pattern = re.sub(r'\(([^)]*\+\)\+', r'(?>\1)+', pattern)
            fixed_pattern = re.sub(r'\(([^)]*\*\)\*', r'(?>\1)*', fixed_pattern)
        elif vulnerability_type == "exponential_backtracking":
            fixed_pattern = re.sub(r'\(\(\\.\*\)\)\*', r'(?>\1+)*', fixed_pattern)
            fixed_pattern = re.sub(r'\(\(\\.\+\)\)\+', r'(?>\1+)+', fixed_pattern)
        
        # Convert to possessive quantifiers
        fixed_pattern = re.sub(r'(\+)(?!\+)', r'\1+', fixed_pattern)
        fixed_pattern = re.sub(r'(\*)(?!\+)', r'\1+', fixed_pattern)
        
        return {
            "original_pattern": pattern,
            "fixed_pattern": fixed_pattern,
            "vulnerability_fixed": vulnerability_type,
            "optimizations_applied": ["atomic_groups", "possessive_quantifiers"]
        }
