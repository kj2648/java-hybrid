import os
import shlex
import subprocess
from pathlib import Path

from jfo.config import Config


class FuzzerRunner:
    def __init__(self, *, cfg: Config):
        self.cfg = cfg

    @staticmethod
    def strip_remainder(xs: list[str]) -> list[str]:
        if not xs:
            return []
        return xs[1:] if xs[0] == "--" else xs

    def run(self, *, launcher: Path, fuzzer_args: list[str], log_path: Path) -> subprocess.Popen:
        corpus = self.cfg.corpus_dir_resolved
        merged = self._apply_default_fuzzer_args(fuzzer_args)
        cmd = self._launcher_argv(launcher) + merged + [str(corpus)]
        log_path.parent.mkdir(parents=True, exist_ok=True)
        lf = open(log_path, "ab", buffering=0)
        env = self._build_env()
        return subprocess.Popen(
            cmd,
            stdout=lf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            cwd=str(self.cfg.work_dir),
            env=env,
        )

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        tmpdir = (self.cfg.work_dir / "tmp").resolve()
        try:
            tmpdir.mkdir(parents=True, exist_ok=True)
        except Exception:
            tmpdir = None
        extra_java_opts = []
        if tmpdir is not None:
            extra_java_opts.append(f"-Djava.io.tmpdir={tmpdir}")
        extra_java_opts += ["-Djdk.attach.allowAttachSelf=true", "-XX:+StartAttachListener"]
        prev = env.get("JAVA_TOOL_OPTIONS", "")
        for opt in extra_java_opts:
            if opt not in prev:
                prev = (prev + " " + opt).strip() if prev else opt
        if prev:
            env["JAVA_TOOL_OPTIONS"] = prev
        return env

    def _apply_default_fuzzer_args(self, fuzzer_args: list[str]) -> list[str]:
        args = list(fuzzer_args)
        if self.cfg.fuzzer_reload and not self._has_flag(args, "-reload"):
            args.append("-reload=1")
        if self.cfg.fuzzer_reload and self.cfg.fuzzer_reload_interval > 0 and not self._has_flag(args, "-reload_interval"):
            args.append(f"-reload_interval={int(self.cfg.fuzzer_reload_interval)}")
        if self.cfg.fuzzer_set_artifact_prefix and not self._has_flag(args, "-artifact_prefix"):
            try:
                self.cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            prefix = str(self.cfg.artifacts_dir.resolve()) + "/"
            args.append(f"-artifact_prefix={prefix}")
        if self.cfg.fuzzer_close_fd_mask is not None and not self._has_flag(args, "-close_fd_mask"):
            args.append(f"-close_fd_mask={int(self.cfg.fuzzer_close_fd_mask)}")
        return args

    @staticmethod
    def _has_flag(argv: list[str], prefix: str) -> bool:
        for a in argv:
            if a == prefix:
                return True
            if a.startswith(prefix + "="):
                return True
            if a.startswith(prefix + ":"):
                return True
        return False

    @staticmethod
    def _launcher_argv(launcher: Path) -> list[str]:
        try:
            if os.access(launcher, os.X_OK):
                return [str(launcher)]
        except Exception:
            pass
        try:
            with launcher.open("r", encoding="utf-8", errors="replace") as f:
                first = f.readline()
        except Exception:
            first = ""
        if first.startswith("#!"):
            shebang = first[2:].strip()
            if shebang:
                return shlex.split(shebang) + [str(launcher)]
        raise SystemExit(f"fuzzer launcher is not executable and has no shebang: {launcher}")
