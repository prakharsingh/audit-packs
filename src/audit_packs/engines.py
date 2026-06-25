import asyncio
import glob
import json
import logging
import os
import tempfile
from abc import ABC, abstractmethod

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = int(os.environ.get("SUBPROCESS_TIMEOUT", "300"))


class BaseEngine(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """The identifier of the engine (e.g. 'checkov', 'semgrep', 'codeql')."""
        pass

    @abstractmethod
    async def run_scan_async(self, target: str, options: dict) -> dict:
        """Asynchronously execute the scan engine on the target and return a SARIF dict."""
        pass

    def run_scan(self, target: str, options: dict) -> dict:
        """Synchronously execute the scan engine on the target and return a SARIF dict."""
        try:
            return asyncio.run(self.run_scan_async(target, options))
        except RuntimeError:
            # Event loop already running fallback (e.g. under pytest or async wrapper)
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    lambda: asyncio.run(self.run_scan_async(target, options))
                )
                return future.result()


class CheckovEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "checkov"

    async def run_scan_async(self, target: str, options: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                cmd = [
                    "checkov",
                    "-d",
                    target,
                    "--output",
                    "sarif",
                    "--output-file-path",
                    tmpdir,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=_DEFAULT_TIMEOUT
                    )
                except asyncio.TimeoutError as exc:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    raise RuntimeError(
                        f"checkov execution timed out after {_DEFAULT_TIMEOUT} seconds"
                    ) from exc

                returncode = proc.returncode
            except Exception as exc:
                if not isinstance(exc, RuntimeError):
                    raise RuntimeError(
                        f"Failed to spawn checkov subprocess: {exc}"
                    ) from exc
                raise

            if returncode is not None and returncode >= 2:
                raise RuntimeError(
                    f"checkov exited with code {returncode}: {stderr.decode(errors='replace').strip()}"
                )

            sarif_file = os.path.join(tmpdir, "results_sarif.sarif")
            if os.path.exists(sarif_file):
                try:
                    with open(sarif_file) as fh:
                        return json.load(fh)
                except json.JSONDecodeError:
                    pass
            return {"runs": []}


class SemgrepEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "semgrep"

    async def run_scan_async(self, target: str, options: dict) -> dict:
        rules_path = options.get("rules_path")
        if not rules_path:
            raise ValueError("semgrep requires 'rules_path' in options")
        try:
            cmd = ["semgrep", "scan", "--config", rules_path, "--sarif", target]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_DEFAULT_TIMEOUT
                )
            except asyncio.TimeoutError as exc:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                raise RuntimeError(
                    f"semgrep execution timed out after {_DEFAULT_TIMEOUT} seconds"
                ) from exc

            returncode = proc.returncode
        except Exception as exc:
            if not isinstance(exc, RuntimeError):
                raise RuntimeError(
                    f"Failed to spawn semgrep subprocess: {exc}"
                ) from exc
            raise

        if returncode is not None and returncode >= 2:
            raise RuntimeError(
                f"semgrep exited with code {returncode}: {stderr.decode(errors='replace').strip()}"
            )

        try:
            return json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError:
            return {"runs": []}


class CodeQLEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "codeql"

    async def run_scan_async(self, target: str, options: dict) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._read_codeql_sarif_sync, target)

    def _read_codeql_sarif_sync(self, sarif_dir: str) -> dict:
        if not os.path.isdir(sarif_dir):
            return {"runs": []}
        runs = []
        for path in glob.glob(os.path.join(sarif_dir, "*.sarif")):
            try:
                with open(path) as fh:
                    data = json.load(fh)
                runs.extend(data.get("runs", []))
            except (json.JSONDecodeError, OSError):
                pass
        return {"runs": runs}


async def run_git_diff_async(workspace: str, base_ref: str) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "git",
            "diff",
            "--unified=0",
            f"{base_ref}...HEAD",
            cwd=workspace,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_DEFAULT_TIMEOUT
            )
        except asyncio.TimeoutError as exc:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise RuntimeError(
                f"git diff execution timed out after {_DEFAULT_TIMEOUT} seconds"
            ) from exc

        if proc.returncode != 0:
            raise RuntimeError(
                f"git diff failed with code {proc.returncode}: {stderr.decode(errors='replace').strip()}"
            )
        return stdout.decode(errors="replace")
    except Exception as exc:
        if not isinstance(exc, RuntimeError):
            raise RuntimeError(f"Failed to run git diff: {exc}") from exc
        raise


def run_git_diff(workspace: str, base_ref: str) -> str:
    try:
        return asyncio.run(run_git_diff_async(workspace, base_ref))
    except RuntimeError:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                lambda: asyncio.run(run_git_diff_async(workspace, base_ref))
            )
            return future.result()


def run_checkov(target_dir: str) -> dict:
    return CheckovEngine().run_scan(target_dir, {})


def run_semgrep(target_dir: str, rules_path: str) -> dict:
    return SemgrepEngine().run_scan(target_dir, {"rules_path": rules_path})


def read_codeql_sarif(sarif_dir: str) -> dict:
    return CodeQLEngine().run_scan(sarif_dir, {})
