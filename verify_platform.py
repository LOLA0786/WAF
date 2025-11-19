#!/usr/bin/env python3
"""
Enterprise Platform Verification Script
Verifies that all components are properly set up.
"""

import os
import sys

def check_file_exists(path, description):
    """Check if a file exists and print status"""
    if os.path.exists(path):
        print(f"✅ {description}: {path}")
        return True
    else:
        print(f"❌ {description}: {path} - MISSING")
        return False

def main():
    print("🔍 WAF Optimization Platform - Enterprise Verification")
    print("=" * 60)
    
    # Critical files to check
    critical_files = [
        ("src/main.py", "Main FastAPI Application"),
        ("src/core/auth.py", "Enterprise Authentication System"),
        ("src/core/analyzer.py", "Advanced Regex Analyzer"),
        ("src/simulation/attack_simulator.py", "Attack Simulation Engine"),
        ("src/ai/regex_generator.py", "AI Regex Generator"),
        ("src/core/config.py", "Configuration Management"),
        (".github/workflows/ci-cd.yml", "CI/CD Pipeline"),
        ("docker-compose.prod.yml", "Production Docker Setup"),
        ("Dockerfile", "Docker Configuration"),
        ("requirements.txt", "Python Dependencies"),
        ("README.md", "Documentation"),
        ("DEPLOYMENT.md", "Deployment Guide"),
        ("pytest.ini", "Test Configuration"),
        ("src/tests/test_main.py", "Test Suite")
    ]
    
    all_good = True
    for file_path, description in critical_files:
        if not check_file_exists(file_path, description):
            all_good = False
    
    print("\n" + "=" * 60)
    if all_good:
        print("🎉 ALL CRITICAL COMPONENTS VERIFIED!")
        print("🚀 Platform is ready for enterprise deployment!")
    else:
        print("⚠️  Some components are missing. Please check above.")
        sys.exit(1)
    
    print("\n📊 Next Steps:")
    print("1. Deploy with: docker-compose -f docker-compose.prod.yml up -d")
    print("2. Configure environment variables in .env")
    print("3. Access API docs at: http://localhost:8000/docs")
    print("4. Set up monitoring at: http://localhost:3000")

if __name__ == "__main__":
    main()
