import json
import os
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from jfo.config import Config


_RE_CP = re.compile(r"--cp=([^ \n]+)")
_RE_TC = re.compile(r"--target_class=([^ \n]+)")

# Avoid JaCoCo report failures due to duplicate Jazzer runtime classes.
_JACOCO_EXCLUDE_JAR_SUBSTRINGS = (
    "jazzer",
    "jazzer_agent",
    "jazzer_agent_deploy",
    "jazzer_standalone",
    "jazzer_bootstrap",
)


@dataclass(frozen=True, slots=True)
class CoverageOutputs:
    report_txt: Path
    exec_file: Path
    html_dir: Path
    log_file: Path
    corpus_out: Path


class CoverageRunner:
    def __init__(self, *, cfg: Config, repo_root: Path | None = None) -> None:
        self.cfg = cfg
        self.repo_root = repo_root or Path(__file__).resolve().parents[2]

    def run(
        self,
        *,
        harness: str,
        launcher: Path,
        fuzzer_runner,
        fuzzer_args: list[str],
        runs: int,
        max_seconds: int | None,
    ) -> int:
        args = self._strip_fuzzer_flags(list(fuzzer_args), ("-jobs", "-workers", "-fork", "-merge"))
        args = self._strip_fuzzer_flags(args, ("--coverage_report", "--coverage_dump"))

        outputs = self._outputs(harness=harness)
        args.append(f"--coverage_report={outputs.report_txt}")
        args.append(f"--coverage_dump={outputs.exec_file}")

        # Ensure the fuzzer exits so the report gets written.
        if (not fuzzer_runner._has_flag(args, "-runs")) and (not fuzzer_runner._has_flag(args, "-max_total_time")):
            args.append(f"-runs={max(1, int(runs or 1))}")
        if max_seconds is not None and int(max_seconds) > 0 and (not fuzzer_runner._has_flag(args, "-max_total_time")):
            args.append(f"-max_total_time={int(max_seconds)}")

        # Keep the main corpus read-only by using a dedicated output corpus for this run.
        corpus_dirs = [outputs.corpus_out, self.cfg.corpus_dir_resolved]

        print(
            f"[Coverage] work_dir={self.cfg.work_dir} harness={harness} "
            f"report={outputs.report_txt} dump={outputs.exec_file} jacoco_html={outputs.html_dir}",
            flush=True,
        )

        proc = fuzzer_runner.run(
            launcher=launcher,
            fuzzer_args=args,
            log_path=outputs.log_file,
            corpus_dirs=corpus_dirs,
        )
        rc = int(proc.wait() or 0)

        jacococli = self.ensure_jacococli_jar()
        if jacococli is None:
            print(
                "[Coverage] note: JaCoCo HTML was not generated (jacococli.jar unavailable). "
                "Auto-download is best-effort; check network access and `third_party/jacoco/`."
            )
            return rc

        ok = self._generate_jacoco_html(jacococli=jacococli, launcher=launcher, exec_path=outputs.exec_file, out_dir=outputs.html_dir, report_name=harness)
        if not ok:
            print("[Coverage] note: JaCoCo HTML generation failed (see logs/fuzzer.coverage.log for the run output).")
        return rc

    def ensure_jacococli_jar(self) -> Path | None:
        third_party = (self.repo_root / "third_party" / "jacoco").resolve()
        jar_path = third_party / "jacococli.jar"
        if jar_path.is_file():
            return jar_path
        try:
            third_party.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"[Coverage] failed to create {third_party}: {e}")
            return None

        version = self._jacoco_version()
        url = (
            "https://repo1.maven.org/maven2/org/jacoco/org.jacoco.cli/"
            f"{version}/org.jacoco.cli-{version}-nodeps.jar"
        )
        tmp = jar_path.with_suffix(".tmp")

        # Prefer system download tools when available (often more reliable than Python SSL on minimal images).
        try:
            if shutil.which("curl"):
                subprocess.run(["curl", "-fsSL", url, "-o", str(tmp)], check=True)
            elif shutil.which("wget"):
                subprocess.run(["wget", "-qO", str(tmp), url], check=True)
            else:
                urllib.request.urlretrieve(url, tmp)
            tmp.replace(jar_path)
        except Exception as e:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            print(f"[Coverage] failed to download jacococli.jar from {url}: {e}")
            return None

        if not jar_path.is_file() or jar_path.stat().st_size < 10_000:
            print(f"[Coverage] downloaded jacococli.jar looks invalid: {jar_path}")
            return None
        return jar_path

    def _jacoco_version(self) -> str:
        mi = self.repo_root / "third_party" / "atl-jazzer" / "maven_install.json"
        try:
            if mi.is_file():
                j = json.loads(mi.read_text(encoding="utf-8"))
                v = (j.get("artifacts", {}) or {}).get("org.jacoco:org.jacoco.core", {}).get("version")
                if isinstance(v, str) and v.strip():
                    return v.strip()
        except Exception:
            pass
        return "0.8.12"

    def _outputs(self, *, harness: str) -> CoverageOutputs:
        cov_dir = (self.cfg.work_dir / "coverage").resolve()
        cov_corpus = cov_dir / "corpus"
        try:
            cov_corpus.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return CoverageOutputs(
            report_txt=cov_dir / f"{harness}.coverage.txt",
            exec_file=cov_dir / f"{harness}.coverage.exec",
            html_dir=cov_dir / f"{harness}.jacoco_html",
            log_file=(self.cfg.logs_dir / "fuzzer.coverage.log"),
            corpus_out=cov_corpus,
        )

    @staticmethod
    def _strip_fuzzer_flags(argv: list[str], prefixes: tuple[str, ...]) -> list[str]:
        out: list[str] = []
        for a in argv:
            drop = False
            for p in prefixes:
                if a == p or a.startswith(p + "=") or a.startswith(p + ":"):
                    drop = True
                    break
            if not drop:
                out.append(a)
        return out

    @staticmethod
    def _parse_classpath_from_launcher(launcher: Path) -> list[Path]:
        try:
            txt = launcher.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        m = _RE_CP.search(txt)
        if not m:
            return []
        cp = m.group(1).strip().strip('"').strip("'")
        base = str(launcher.parent.resolve())
        cp = cp.replace("$this_dir", base).replace("${this_dir}", base)
        out: list[Path] = []
        for part in cp.split(":"):
            part = part.strip()
            if not part:
                continue
            p = Path(os.path.expandvars(part)).expanduser()
            out.append(p)
        return out

    @staticmethod
    def _parse_target_class_from_launcher(launcher: Path) -> str | None:
        try:
            txt = launcher.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None
        m = _RE_TC.search(txt)
        if not m:
            return None
        tc = m.group(1).strip().strip('"').strip("'")
        return tc or None

    @staticmethod
    def _target_class_file_relpath(target_class: str) -> Path:
        # "pkg.Class" -> "pkg/Class.class", "Class" -> "Class.class"
        return Path(*target_class.split(".")).with_suffix(".class")

    @classmethod
    def _looks_like_jazzer_jar(cls, p: Path) -> bool:
        name = p.name.lower()
        return any(s in name for s in _JACOCO_EXCLUDE_JAR_SUBSTRINGS)

    def _select_classfiles_for_report(self, launcher: Path) -> list[Path]:
        """
        Select a safe set of classfiles for jacococli `report`:
        - include non-Jazzer jars from the fuzz target classpath
        - include the fuzz target .class file (if found) instead of scanning the whole out/ dir
        This avoids JaCoCo errors like "Can't add different class with same name".
        """
        cp_entries = self._parse_classpath_from_launcher(launcher)
        target_class = self._parse_target_class_from_launcher(launcher)

        jars: list[Path] = []
        dirs: list[Path] = []
        for p in cp_entries:
            try:
                rp = p.expanduser().resolve()
            except Exception:
                rp = p
            if rp.is_dir():
                dirs.append(rp)
            elif rp.is_file() and rp.suffix.lower() == ".jar":
                if not self._looks_like_jazzer_jar(rp):
                    jars.append(rp)

        classfiles: list[Path] = []
        classfiles.extend(jars)

        if target_class:
            rel = self._target_class_file_relpath(target_class)
            for d in dirs:
                cand = (d / rel)
                if cand.is_file():
                    classfiles.append(cand)
                    break

        # De-dup while preserving order.
        seen: set[Path] = set()
        uniq: list[Path] = []
        for p in classfiles:
            try:
                key = p.resolve()
            except Exception:
                key = p
            if key in seen:
                continue
            seen.add(key)
            uniq.append(p)
        return uniq

    def _generate_jacoco_html(self, *, jacococli: Path, launcher: Path, exec_path: Path, out_dir: Path, report_name: str) -> bool:
        if not exec_path.is_file():
            return False
        classfiles = [p for p in self._select_classfiles_for_report(launcher) if p.exists()]
        if not classfiles:
            print(f"[Coverage] could not select any classfiles for report from {launcher}")
            return False
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        cmd: list[str] = ["java", "-jar", str(jacococli), "report", str(exec_path), "--html", str(out_dir), "--name", report_name]
        for p in classfiles:
            cmd += ["--classfiles", str(p)]
        try:
            subprocess.run(cmd, check=False)
        except Exception as e:
            print(f"[Coverage] failed to run jacococli: {e}")
            return False
        return (out_dir / "index.html").is_file()
