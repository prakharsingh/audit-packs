import os
import tempfile
import yaml
from audit_packs_action.engines import DeclarativeEngine
from audit_packs_action.cli import pack_init, pack_validate, handle_pack_subcommand


def test_declarative_engine_loading():
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "my_scanner.yaml")
        cfg = {
            "id": "mock-scanner",
            "title": "Mock Scanner Plugin",
            "executable": "echo",
            "args": ["{target_dir}", "{output_file}"],
            "output_format": "sarif",
        }
        with open(config_path, "w") as fh:
            yaml.safe_dump(cfg, fh)

        # Initialize declarative engine
        engine = DeclarativeEngine(config_path)
        assert engine.name == "mock-scanner"
        assert engine.executable == "echo"
        assert engine.args_template == ["{target_dir}", "{output_file}"]


def test_pack_init_and_validate():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize a pack
        ret = pack_init("my-test-pack", tmpdir)
        assert ret == 0

        pack_path = os.path.join(tmpdir, "my-test-pack")
        assert os.path.exists(os.path.join(pack_path, "controls.yaml"))
        assert os.path.exists(os.path.join(pack_path, "metadata.json"))

        # Validate the generated pack
        ret_val = pack_validate(pack_path)
        assert ret_val == 0

        # Test handle_pack_subcommand dispatch
        ret_val_sub = handle_pack_subcommand(["validate", pack_path])
        assert ret_val_sub == 0


def test_pack_publish_and_install():
    from audit_packs_action.cli import pack_publish, pack_install

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Initialize a pack
        pack_dir = os.path.join(tmpdir, "source")
        os.makedirs(pack_dir, exist_ok=True)
        ret = pack_init("my-registry-pack", pack_dir)
        assert ret == 0

        # 2. Package / Publish the pack
        publish_dir = os.path.join(tmpdir, "publish")
        os.makedirs(publish_dir, exist_ok=True)
        ret_pub = pack_publish(os.path.join(pack_dir, "my-registry-pack"), publish_dir)
        assert ret_pub == 0

        tarball_path = os.path.join(publish_dir, "my-registry-pack-0.1.0.tar.gz")
        assert os.path.exists(tarball_path)

        # 3. Install the pack
        install_dir = os.path.join(tmpdir, "install")
        os.makedirs(install_dir, exist_ok=True)
        ret_inst = pack_install(tarball_path, install_dir)
        assert ret_inst == 0

        installed_pack_path = os.path.join(install_dir, "my-registry-pack")
        assert os.path.exists(installed_pack_path)
        assert os.path.exists(os.path.join(installed_pack_path, "controls.yaml"))
        assert os.path.exists(os.path.join(installed_pack_path, "metadata.json"))
