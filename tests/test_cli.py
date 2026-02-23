import io
import unittest
from contextlib import redirect_stdout

from src.waterapps_vault import cli


class CliTests(unittest.TestCase):
    def test_parse_kv_pairs(self):
        self.assertEqual(cli.parse_kv_pairs(["a=1", "b=two=2"]), {"a": "1", "b": "two=2"})

    def test_parse_kv_pairs_rejects_invalid(self):
        with self.assertRaises(ValueError):
            cli.parse_kv_pairs(["missing"])

    def test_export_env_cmd_formats_prefix(self):
        class FakeClient:
            def kv_read(self, mount, path):
                return {"access_token": "abc", "author_urn": "urn:li:person:1"}

        with unittest.mock.patch("src.waterapps_vault.cli.client_from_env", return_value=FakeClient()):
            args = type("Args", (), {"mount": "secret", "path": "waterapps/x", "fields": ["access_token"], "prefix": "LINKEDIN_"})
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli.cmd_export_env(args)
            self.assertEqual(rc, 0)
            self.assertIn("export LINKEDIN_ACCESS_TOKEN=abc", buf.getvalue())

    def test_export_env_cmd_shell_quotes_values_and_skips_unsafe_names(self):
        class FakeClient:
            def kv_read(self, mount, path):
                return {
                    "good_key": '$(touch /tmp/pwned)\nline2',
                    "bad-key": "x",
                }

        with unittest.mock.patch("src.waterapps_vault.cli.client_from_env", return_value=FakeClient()):
            args = type("Args", (), {"mount": "secret", "path": "waterapps/x", "fields": None, "prefix": "SAFE_"})
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), unittest.mock.patch("sys.stderr", err):
                rc = cli.cmd_export_env(args)
            self.assertEqual(rc, 0)
            self.assertIn("export SAFE_GOOD_KEY='$(touch /tmp/pwned)", out.getvalue())
            self.assertIn("Unsafe env var name", err.getvalue())


if __name__ == "__main__":
    unittest.main()
