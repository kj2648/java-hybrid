import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_RE_CP = re.compile(r"--cp=([^ \n]+)")
_RE_TC = re.compile(r"--target_class=([^ \n]+)")
_RE_JVM_ARGS = re.compile(r"--jvm_args=(\"[^\"]*\"|'[^']*'|[^ \n]+)")
_RE_EXPORT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class JazzerLauncherInfo:
    launcher: Path
    launcher_dir: Path
    classpath: str
    target_class: str
    java_home: Optional[Path]
    ld_library_path: Optional[str]
    jvm_args: Optional[str]


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s


def _resolve_shell_vars(s: str, vars_map: dict[str, str]) -> str:
    """
    Minimal variable interpolation for common launcher patterns.
    Supports $VAR and ${VAR}.
    """
    for k, v in vars_map.items():
        s = s.replace(f"${{{k}}}", v).replace(f"${k}", v)
    return s


def _find_assignments(txt: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _RE_EXPORT.finditer(txt):
        var = m.group(1)
        val = _strip_quotes(m.group(2))
        # Avoid capturing very complex shell expansions. We only need simple vars.
        if "$(" in val or "`" in val:
            continue
        out.setdefault(var, val)
    return out


def parse_jazzer_launcher(launcher: Path) -> JazzerLauncherInfo:
    launcher = launcher.resolve()
    txt = launcher.read_text(encoding="utf-8", errors="replace")
    cp_m = _RE_CP.search(txt)
    tc_m = _RE_TC.search(txt)
    cp_arg = cp_m.group(1) if cp_m else ""
    target_class = tc_m.group(1) if tc_m else ""
    if not cp_arg or not target_class:
        raise ValueError(f"failed to parse --cp/--target_class from launcher: {launcher}")

    this_dir = str(launcher.parent.resolve())
    cp = cp_arg.replace("$this_dir", this_dir).replace("${this_dir}", this_dir)
    cp = cp.replace("::", ":")

    assigns = _find_assignments(txt)

    # Best-effort variable resolution for common launcher patterns.
    vars_map: dict[str, str] = {"this_dir": this_dir}
    for _ in range(2):
        for k, v in assigns.items():
            vars_map.setdefault(k, _resolve_shell_vars(v, vars_map))

    java_home_raw = assigns.get("JAVA_HOME")
    java_home = None
    if java_home_raw:
        resolved = _resolve_shell_vars(java_home_raw, vars_map)
        java_home = Path(resolved).expanduser()
        if not java_home.is_absolute():
            java_home = (launcher.parent / java_home).resolve()
        else:
            java_home = java_home.resolve()

    if java_home is not None:
        vars_map["JAVA_HOME"] = str(java_home)

    ld_raw = assigns.get("LD_LIBRARY_PATH")
    ld = _resolve_shell_vars(ld_raw, vars_map) if ld_raw else None

    jvm_m = _RE_JVM_ARGS.search(txt)
    jvm_args = None
    if jvm_m:
        jvm_args = _resolve_shell_vars(_strip_quotes(jvm_m.group(1)), vars_map)

    return JazzerLauncherInfo(
        launcher=launcher,
        launcher_dir=launcher.parent.resolve(),
        classpath=cp,
        target_class=target_class,
        java_home=java_home,
        ld_library_path=ld,
        jvm_args=jvm_args,
    )


def pick_java_binaries(info: JazzerLauncherInfo) -> tuple[str, str]:
    """
    OSS-Fuzz Jazzer targets often carry an OpenJDK 8 under the launcher dir.
    Falls back to system java/javac if absent.
    """
    if info.java_home is not None:
        java = info.java_home / "bin" / "java"
        javac = info.java_home / "bin" / "javac"
        if java.exists() and javac.exists():
            return str(java), str(javac)

    java = "java"
    javac = "javac"
    for sub in ("bin", "jre/bin"):
        cand = info.launcher_dir / "open-jdk-8" / sub / "java"
        if cand.exists():
            java = str(cand)
        cand = info.launcher_dir / "open-jdk-8" / sub / "javac"
        if cand.exists():
            javac = str(cand)
    return java, javac


def build_launcher_env(info: JazzerLauncherInfo, base_env: Optional[dict[str, str]] = None) -> dict[str, str]:
    """
    Build a process env consistent with the launcher:
    - Set JAVA_HOME from parsed launcher (if present and missing in base env)
    - Apply launcher LD_LIBRARY_PATH, expanding $LD_LIBRARY_PATH and $JAVA_HOME against base env
    """
    env = (base_env or os.environ).copy()

    if info.java_home is not None and not env.get("JAVA_HOME"):
        env["JAVA_HOME"] = str(info.java_home)

    if info.ld_library_path:
        current_ld = env.get("LD_LIBRARY_PATH", "")
        expanded = info.ld_library_path.replace("${LD_LIBRARY_PATH}", current_ld).replace("$LD_LIBRARY_PATH", current_ld)
        java_home = env.get("JAVA_HOME", "")
        expanded = expanded.replace("${JAVA_HOME}", java_home).replace("$JAVA_HOME", java_home)
        env["LD_LIBRARY_PATH"] = expanded

    return env


def javac_args_for_java8(javac: str) -> list[str]:
    """
    Return common javac args for compiling Java 8 compatible bytecode.
    """
    args = [javac, "-g"]
    if _javac_supports_release(javac):
        return args + ["--release", "8"]
    return args + ["-source", "8", "-target", "8"]


def pick_jvm_opts(
    env: dict[str, str],
    info: JazzerLauncherInfo,
    *,
    env_key: str,
    default: str,
) -> list[str]:
    """
    Priority:
      1) env[env_key]
      2) launcher --jvm_args (jazzer style)
      3) default
    """
    raw = (env.get(env_key) or "").strip()
    if not raw:
        raw = (info.jvm_args or "").strip()
    if not raw:
        raw = default

    # Jazzer commonly uses colon-separated JVM args (no spaces).
    if ":" in raw and " " not in raw and "\t" not in raw:
        opts = [p for p in raw.split(":") if p]
    else:
        opts = shlex.split(raw)

    for token in opts:
        if token and not (token.startswith("-") or token.startswith("@")):
            raise SystemExit(
                f"[spf] invalid JVM option token: {token}\n"
                f"derived from: {raw}\n"
                "Hint: launcher --jvm_args must expand to valid JVM options (e.g. -Xmx2g), "
                "not an unexpanded shell variable."
            )
    return opts


def _javac_supports_release(javac: str) -> bool:
    try:
        out = subprocess.check_output([javac, "-help"], stderr=subprocess.STDOUT, text=True)
        return "--release" in out
    except Exception:
        return False
