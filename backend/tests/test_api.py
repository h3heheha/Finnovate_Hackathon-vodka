from fastapi.testclient import TestClient

from app.knowledge import loader
from app.main import app

client = TestClient(app)
API = "/api/v1"


def sample(id_: str) -> str:
    return next(s["text"] for s in loader.samples() if s["id"] == id_)


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_analyze_endpoint_shape():
    r = client.post(f"{API}/analyze", json={"text": sample("fake_bank")})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_level"] == "high"
    assert body["tactics"] and body["segments"] and body["advice"]


def test_validation_rejects_empty_text():
    assert client.post(f"{API}/analyze", json={"text": ""}).status_code == 422


def test_pause_before_pay_for_account_from_scam_message():
    scan = client.post(f"{API}/analyze", json={"text": sample("hi_mum")}).json()
    account = scan["entities"]["accounts"][0]
    check = client.post(f"{API}/payments/check", json={
        "payee_account": account, "amount": 18500, "source_analysis_id": scan["analysis_id"],
    }).json()
    assert check["decision"] == "pause"
    assert check["cooldown_seconds"] > 0
    # Same account entered manually later (no link to the scan) is still caught.
    again = client.post(f"{API}/payments/check", json={"payee_account": account, "amount": 500}).json()
    assert again["decision"] == "pause"


def test_normal_payment_allowed():
    r = client.post(f"{API}/payments/check", json={
        "payee_account": "111122223333", "amount": 800, "is_saved_payee": True, "reference": "Rent May",
    }).json()
    assert r["decision"] == "allow"


def test_content_endpoints():
    assert len(client.get(f"{API}/samples").json()) >= 5
    assert client.get(f"{API}/learn/tactics").json()[0]["lesson"]
    assert client.get(f"{API}/learn/quiz").json()
    assert client.get(f"{API}/directory").json()["organisations"]
    assert "total_checks" in client.get(f"{API}/radar").json()


def test_feedback():
    scan = client.post(f"{API}/analyze", json={"text": "hello"}).json()
    assert client.post(f"{API}/feedback", json={"analysis_id": scan["analysis_id"], "verdict": "legit"}).status_code == 200
    assert client.post(f"{API}/feedback", json={"analysis_id": "nope", "verdict": "legit"}).status_code == 404
