import shutil
import subprocess
import os
import pytest

# Determine script directory
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SMOKE_TEST_SCRIPT = os.path.join(TEST_DIR, "docker_smoke.sh")


def has_docker():
    """Check if docker CLI is available and the daemon is reachable."""
    if shutil.which("docker") is None:
        return False
    try:
        res = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=5
        )
        return res.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


# Skip this test module if docker daemon is not available or SKIP_DOCKER_TESTS is set
pytestmark = pytest.mark.skipif(
    not has_docker() or os.environ.get("SKIP_DOCKER_TESTS") == "true",
    reason="Docker is not installed/daemon not running or SKIP_DOCKER_TESTS is set",
)


def test_docker_image_smoke():
    """Verify that the Docker image builds and runs successfully, emitting the expected outputs."""
    # Ensure the script is executable
    os.chmod(SMOKE_TEST_SCRIPT, 0o755)

    # Run the smoke test shell script
    res = subprocess.run(
        [SMOKE_TEST_SCRIPT],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(TEST_DIR),
        timeout=600,  # 10 minutes limit in case image needs to build from scratch
    )

    # Print output for debugging in case of failure
    print("STDOUT:")
    print(res.stdout)
    print("STDERR:")
    print(res.stderr)

    assert (
        res.returncode == 0
    ), f"Docker smoke test script failed with exit code {res.returncode}"
