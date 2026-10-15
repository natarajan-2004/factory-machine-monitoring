from fastapi.testclient import TestClient
from app.main import app

# These smoke tests validate the API contract against the configured database.
def test_health():
    with TestClient(app) as client:
        response=client.get('/health')
        assert response.status_code == 200
        assert response.json()['status'] == 'ok'

def test_login_and_machine_list():
    with TestClient(app) as client:
        response=client.post('/auth/login',json={'email':'admin@factory.local','password':'Admin123!'})
        assert response.status_code == 200
        token=response.json()['access_token']
        machines=client.get('/api/machines',headers={'Authorization':f'Bearer {token}'})
        assert machines.status_code == 200
        assert len(machines.json()) >= 1
