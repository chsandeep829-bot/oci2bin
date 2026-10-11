"""RUN gives host helpers a fixed environment and exports image ENV in chroot."""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "dockerfile_build", ROOT / "scripts" / "dockerfile_build.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class RunEnvTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name) / "rootfs"
        (root / "bin").mkdir(parents=True)
        (root / "bin" / "sh").write_text("dummy")
        self.state = MOD._State(self.tmp.name, {}, {}, "amd64")
        self.state.rootfs = str(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_host_helpers_never_receive_image_env(self):
        self.state.env = ["PATH=/malicious/bin", "LD_PRELOAD=/malicious/lib.so",
                          "VALUE=quoted' value"]
        self.state.build_args = {"AWS_SECRET_ACCESS_KEY": "sentinel"}
        with mock.patch.object(MOD.subprocess, "run") as run:
            MOD._do_run(self.state, "true")
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "unshare")
        host_env = kwargs["env"]
        self.assertEqual(host_env["PATH"],
                         "/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                         "/usr/bin:/sbin:/bin")
        self.assertNotIn("LD_PRELOAD", host_env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", host_env)
        inner = args[0][-1]
        self.assertIn("export PATH=/malicious/bin", inner)
        self.assertIn("export LD_PRELOAD=/malicious/lib.so", inner)
        self.assertIn("export AWS_SECRET_ACCESS_KEY=sentinel", inner)
        self.assertIn("quoted", inner)
        self.assertLess(inner.index("chroot "), inner.index("export PATH="))

    def test_invalid_environment_name_fails_closed(self):
        self.state.env = ["X;touch /tmp/bad=value"]
        with mock.patch.object(MOD.subprocess, "run") as run:
            with self.assertRaises(SystemExit):
                MOD._do_run(self.state, "true")
        run.assert_not_called()

    def test_cache_mount_cannot_select_parent_or_symlink(self):
        host_home = pathlib.Path(self.tmp.name) / "home"
        host_home.mkdir()
        with mock.patch.dict(os.environ, {"HOME": str(host_home)}):
            with self.assertRaises(SystemExit):
                MOD._mount_cache({"target": "/cache", "id": ".."},
                                 self.state)
            cache_root = host_home / ".cache" / "oci2bin" / "build-cache"
            cache_root.mkdir(parents=True)
            (cache_root / "escape").symlink_to(host_home)
            with self.assertRaises(SystemExit):
                MOD._mount_cache({"target": "/cache", "id": "escape"},
                                 self.state)


if __name__ == "__main__":
    unittest.main()
