# SPF Docker workflow

This repository can run SPF (jpf-core + jpf-symbc) inside a container to avoid
host JDK/version issues.

This workflow is standardized on JDK 8.

## Build image

`scripts/spf_docker.sh build`

## Clone + build SPF deps (inside container)

`scripts/spf_docker.sh setup`

This populates `third_party/spf/` and generates `scripts/spf_env.sh`.

## Configure target

Edit `scripts/spf_env.sh`:
- `SPF_TARGET`
- `SPF_CLASSPATH`

## Run orchestrator (inside container)

`scripts/spf_docker.sh run --corpus /path/to/corpus --workers 2 --fuzzer-path /path/to/FuzzerLauncher --mode atl`

## Run SPF once (example)

If you built a Jazzer-style OSS-Fuzz launcher on the host, run it via an extra mount:

`scripts/spf_docker.sh run-once --launcher /path/to/oss-fuzz/build/out/<project>/<FuzzerName> --seed /path/to/seedfile`

You can tweak behavior via env vars:
- `SPF_SYMBOLIC_ARRAYS=false`
- `SPF_USE_SYMBOLIC_LISTENER=1`
