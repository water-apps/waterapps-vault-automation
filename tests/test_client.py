import json
import unittest
from unittest import mock

from src.waterapps_vault import client


class FakeResponse:
    def __init__(self, payload, code=200):
        self._payload = payload
        self._code = code

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def getcode(self):
        return self._code

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class VaultClientTests(unittest.TestCase):
    def test_build_kv_v2_read_url(self):
        url = client.build_kv_v2_read_url("https://vault.example.com/", "secret", "/waterapps/linkedin")
        self.assertEqual(url, "https://vault.example.com/v1/secret/data/waterapps/linkedin")

    def test_build_jwt_login_url(self):
        url = client.build_jwt_login_url("https://vault.example.com", auth_mount="github-jwt")
        self.assertEqual(url, "https://vault.example.com/v1/auth/github-jwt/login")

    def test_rejects_non_https_non_localhost_vault_addr(self):
        with self.assertRaises(client.VaultError):
            client.build_kv_v2_read_url("http://vault.example.com", "secret", "x")

    def test_allows_http_for_localhost_vault_addr(self):
        url = client.build_kv_v2_read_url("http://127.0.0.1:8200", "secret", "x")
        self.assertEqual(url, "http://127.0.0.1:8200/v1/secret/data/x")

    @mock.patch("src.waterapps_vault.client.urllib.request.urlopen")
    def test_jwt_login_sets_client_token(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"auth": {"client_token": "vault-token", "lease_duration": 3600}})
        vc = client.VaultClient("https://vault.example.com")
        payload = vc.jwt_login(role="github-role", jwt="jwt-token")
        self.assertEqual(vc.token, "vault-token")
        self.assertEqual(payload["auth"]["lease_duration"], 3600)

    @mock.patch("src.waterapps_vault.client.urllib.request.urlopen")
    def test_kv_read_parses_kv_v2_data(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"data": {"data": {"access_token": "abc", "author_urn": "urn:li:person:1"}}})
        vc = client.VaultClient("https://vault.example.com", token="vault-token")
        data = vc.kv_read("secret", "waterapps/linkedin-publisher")
        self.assertEqual(data["access_token"], "abc")
        self.assertEqual(data["author_urn"], "urn:li:person:1")

    @mock.patch("src.waterapps_vault.client.urllib.request.urlopen")
    def test_kv_write_wraps_data_for_kv_v2(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"data": {"version": 3}})
        vc = client.VaultClient("https://vault.example.com", token="vault-token")
        vc.kv_write("secret", "waterapps/linkedin-publisher", {"k": "v"})
        req = mock_urlopen.call_args.args[0]
        self.assertEqual(req.method, "POST")
        self.assertIn("/v1/secret/data/waterapps/linkedin-publisher", req.full_url)
        body = json.loads(req.data.decode("utf-8"))
        self.assertEqual(body, {"data": {"k": "v"}})


if __name__ == "__main__":
    unittest.main()
