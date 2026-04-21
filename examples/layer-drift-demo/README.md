# Layer Drift Demo

This is a tiny project you can use to demonstrate what layer drift means in practice.

It gives you one baseline image and four drift variants:

- `baseline`: the reference image
- `extra`: adds an extra filesystem layer
- `missing`: removes a layer that existed in the baseline
- `reordered`: keeps the same files but changes layer order
- `changed`: keeps the same rough shape but changes file contents

## Files

- [Dockerfile.baseline](/home/danchi/projects/go/provavalidator/examples/layer-drift-demo/Dockerfile.baseline)
- [Dockerfile.extra](/home/danchi/projects/go/provavalidator/examples/layer-drift-demo/Dockerfile.extra)
- [Dockerfile.missing](/home/danchi/projects/go/provavalidator/examples/layer-drift-demo/Dockerfile.missing)
- [Dockerfile.reordered](/home/danchi/projects/go/provavalidator/examples/layer-drift-demo/Dockerfile.reordered)
- [Dockerfile.changed](/home/danchi/projects/go/provavalidator/examples/layer-drift-demo/Dockerfile.changed)
- [build-images.sh](/home/danchi/projects/go/provavalidator/examples/layer-drift-demo/build-images.sh)

## Build The Demo Images

From the repo root:

```bash
cd examples/layer-drift-demo
./build-images.sh
```

That builds these local tags:

- `layer-drift-demo:baseline`
- `layer-drift-demo:extra`
- `layer-drift-demo:missing`
- `layer-drift-demo:reordered`
- `layer-drift-demo:changed`

## Run The Drift Checks

From the repo root:

```bash
./provavalidator drift layer-drift-demo:extra --baseline layer-drift-demo:baseline
./provavalidator drift layer-drift-demo:missing --baseline layer-drift-demo:baseline
./provavalidator drift layer-drift-demo:reordered --baseline layer-drift-demo:baseline
./provavalidator drift layer-drift-demo:changed --baseline layer-drift-demo:baseline
```

If you want the command to report drift but not fail the shell command, add:

```bash
--fail-on-drift=false
```

## What Each Variant Demonstrates

`extra`

Adds a new `RUN` layer that creates a debug marker. This is the clearest example of "the image gained a layer."

`missing`

Drops one of the copy steps from the baseline. This shows "the image lost expected filesystem history."

`reordered`

Copies the same files as the baseline, but in a different order. Since provavalidator compares uncompressed `DiffIDs`, this is still meaningful drift.

`changed`

Copies a different application file while keeping the build structure similar. This demonstrates "same-looking image, different filesystem content."

## Useful Policy Demos

Allow extra layers, but still reject missing or reordered ones:

```bash
./provavalidator drift layer-drift-demo:extra \
  --baseline layer-drift-demo:baseline \
  --allow-extra \
  --fail-on-drift=true
```

Allow reordered layers:

```bash
./provavalidator drift layer-drift-demo:reordered \
  --baseline layer-drift-demo:baseline \
  --allow-reorder
```

## Good Demo Flow

1. Build the five images.
2. Run `baseline` vs `extra` to show a very obvious added layer.
3. Run `baseline` vs `reordered` to explain why layer order matters.
4. Run `baseline` vs `changed` to show that "same app idea" does not mean "same filesystem truth."
5. Re-run with `--allow-extra` or `--allow-reorder` to demonstrate policy tuning.
