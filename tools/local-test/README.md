# Local offline test container

Runs the offline check chain for the Terraform Landing Zone in a container with
a pinned toolchain, so the static and test layers run on any machine with a
container runtime.

This is the **offline mirror** of the check chain (`make fmt / validate / lint
/ scan / test`). It reaches **no AWS** and needs **no credentials**. It is not
a substitute for an apply against real accounts, which verifies behaviour.

## Usage

From anywhere in the repository (the wrapper finds the root itself):

```bash
tools/local-test/run.sh                # build + run `make all`
tools/local-test/run.sh make test      # run a specific target
TLZ_CONTAINER_ENGINE=finch tools/local-test/run.sh   # use Finch
```

The container runs with `--network none`, so it cannot reach AWS or any other
network endpoint even if a target tried to.

## Pinned toolchain

| Tool | Version |
|---|---|
| Terraform | 1.16.1 |
| Terragrunt | 1.1.4 |
| TFLint | 0.64.0 |
| Python | 3.12 |
| pytest / hypothesis / checkov | see `requirements.txt` |

The build is reproducible from `Containerfile` + `requirements.txt` alone; no
step reaches AWS, none runs `local-exec`, and there is no deployment path.

## Docker vs Finch — the one divergence

Docker on native Linux is the primary runtime. Finch works with the same image
and the same `run.sh`; the image, its layers, and the check chain are identical
between them. The **only** difference: on Finch, prefer a native-architecture
VM (linux/arm64 on Graviton, linux/amd64 on x86) so the tool-download layers in
the `Containerfile` resolve to the host architecture (`TARGETARCH`) without
emulation. Under Docker on native Linux this is automatic.
