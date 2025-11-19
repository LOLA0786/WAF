import pytest
import asyncio
from fastapi.testclient import TestClient
from src.main import app
from src.core.auth import EnterpriseAuthManager, UserRole
from src.core.analyzer import EnterpriseRegexAnalyzer
from src.ai.regex_generator import AIRegexGenerator

client = TestClient(app)

class TestAuthentication:
    def test_create_user(self):
        auth_manager = EnterpriseAuthManager()
        user = auth_manager.create_user("test@example.com", UserRole.EDITOR)
        assert user.email == "test@example.com"
        assert user.role == UserRole.EDITOR
    
    def test_generate_token(self):
        auth_manager = EnterpriseAuthManager()
        user = auth_manager.create_user("test@example.com", UserRole.EDITOR)
        token = auth_manager.generate_api_token(user.user_id)
        assert token.token is not None
        assert token.user_id == user.user_id

class TestRegexAnalysis:
    def test_analyze_simple_pattern(self):
        analyzer = EnterpriseRegexAnalyzer()
        analysis = analyzer.analyze_pattern(r"\w+@\w+\.\w+")
        assert analysis.security_level.value in ["low", "medium", "high", "critical"]
        assert analysis.complexity_score >= 0
    
    def test_analyze_complex_pattern(self):
        analyzer = EnterpriseRegexAnalyzer()
        analysis = analyzer.analyze_pattern(r"(a+)+b")
        assert analysis.security_level.value == "critical"
        assert "Nested quantifiers" in analysis.vulnerability_types

class TestAIComponents:
    def test_ai_regex_generation(self):
        generator = AIRegexGenerator()
        result = generator.generate_from_natural_language("email validation")
        assert "pattern" in result
        assert result["security_score"] > 0

class TestAPIEndpoints:
    def test_health_endpoint(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_ai_regex_endpoint(self):
        response = client.post("/ai/generate-regex", json={
            "description": "email validation",
            "security_level": "enterprise"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["success"] == True

@pytest.fixture
def test_client():
    return TestClient(app)

@pytest.mark.asyncio
async def test_concurrent_requests(test_client):
    """Test handling of concurrent requests"""
    async def make_request():
        response = test_client.get("/health")
        return response.status_code
    
    tasks = [make_request() for _ in range(10)]
    results = await asyncio.gather(*tasks)
    assert all(result == 200 for result in results)
