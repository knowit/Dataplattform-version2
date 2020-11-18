import pytest
import os

os.environ.pop('STAGE')
import app  # noqa: E402


@pytest.fixture
def client():
    app.app.config['TESTING'] = True

    with app.app.test_client() as client:
        yield client


def test_database_route(client):
    response = client.get('/catalogue/database/test_database')
    assert response.status_code == 200


def test_database_content(client):
    response = client.get('/catalogue/database/test_database')
    res = response.json
    assert all([
        res is not None,
        res['tables'][0] == 'test_table',
        res['name'] == 'test_database'
    ])


def test_database_route_404(client):
    response = client.get('/catalogue/database/test_database1')
    assert response.status_code == 404


def test_database_route_404_ignore(client):
    response = client.get('/catalogue/database/default')
    assert response.status_code == 404


def test_database_table_route_404_ignore(client):
    response = client.get('/catalogue/database/default/test_table')
    assert response.status_code == 404


def test_table_route(client):
    response = client.get('/catalogue/database/test_database/table/test_table')
    assert response.status_code == 200


def test_database_table_route_404(client):
    response = client.get('/catalogue/database/test_database/table/test_table1')
    assert response.status_code == 404


def test_database_table_content(client):
    response = client.get('/catalogue/database/test_database/table/test_table')
    res = response.json
    assert all([
        res['columns'] is not None,
        res['columns'][0]['name'] == 'col1'
    ])


def test_table_route_404(client):
    response = client.get('/catalogue/table/test_table1')
    assert response.status_code == 404


def test_table_route_404_ignore(client):
    response = client.get('/catalogue/table/default')
    assert response.status_code == 404


def test_table_content(client):
    response = client.get('/catalogue/table/test_table')
    res = response.json
    assert all([
        res['columns'] is not None,
        res['columns'][0]['name'] == 'col1'
    ])


def test_databases_route(client):
    response = client.get('/catalogue/database')
    assert response.status_code == 200


def test_databases_route_content(client):
    response = client.get('/catalogue/database')
    res = response.json
    assert all([
        res[0]['tables'][0] == 'test_table',
        res[0]['name'] == 'test_database'
    ])


def test_tables_route(client):
    response = client.get('/catalogue/table')
    assert response.status_code == 200


def test_tables_route_content(client):
    response = client.get('/catalogue/table')
    res = response.json
    assert all([
        res[0]['columns'] is not None,
        res[0]['columns'][0]['name'] == 'col1'
    ])
