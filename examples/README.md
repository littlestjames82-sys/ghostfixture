# GhostFixture walkthrough

A five-minute tour using the demo project in this folder.

## What is in this folder

- `demo_project/` - a tiny Python project with four modules:
  - `demo/pricing.py` - the module a task was about.
  - `demo/rates.py` - imported by pricing.py, nothing else.
  - `demo/keys.py` - holds a fake, example-only secret-shaped
    literal, planted on purpose.
  - `demo/scratch.py` - unreferenced scratch work.
- `demo_bundle/` - a GhostSlice-shaped bundle cut from the demo
  project. It references only pricing.py and keys.py. Regenerate
  it any time with `python3 examples/make_demo_bundle.py`.
- `make_demo_bundle.py` - the small script that writes the demo
  bundle, so its hashes always match the demo project.

## Step 1: build the fixture

From the repository root, with the package installed or with
`PYTHONPATH=src`:

```sh
ghostfixture build examples/demo_project examples/demo_bundle \
    -o /tmp/demo-fixture --task "Fix the tax rounding in pricing.py"
```

Expected output, in substance:

```
GhostFixture built: /tmp/demo-fixture
  Size cap: 2097152 bytes (total copied content)
  Included: 3 files, 414 bytes (bundle-referenced first, then static import closure)
  excluded-flagged: demo/keys.py [stripe-key]
  Record: fixture-manifest.json + FIXTURE.md in /tmp/demo-fixture
```

## Step 2: look at what you got

```
/tmp/demo-fixture/
  fixture-manifest.json
  FIXTURE.md
  demo/
    __init__.py    (package chain, import-closure)
    pricing.py     (bundle-referenced, copied from the original)
    rates.py       (import-closure, via demo/pricing.py)
```

Three things to notice:

1. **rates.py came along even though the bundle never named
   it.** pricing.py imports it, so a fixture without it would
   not even parse. The manifest records it with reason
   `import-closure` and names pricing.py as the importer.
2. **keys.py is not there.** It was referenced by the bundle,
   but it carries a secret-shaped literal, so it was excluded
   and recorded under `excluded_flagged` by path and pattern
   type only. Its value appears nowhere in the fixture tree.
   Note the honest boundary: the demo bundle itself still holds
   the sliced text Slice cut, because that bundle was made
   before Fixture ran. Fixture governs the tree it builds, not
   artifacts that already exist.
3. **scratch.py is not there either.** Nothing referenced it
   and nothing imports it, so it stays behind. That is the
   "minimal" in minimal repro project.

## Step 3: verify the fixture later

```sh
ghostfixture check /tmp/demo-fixture
```

This re-reads fixture-manifest.json, confirms every included
file is present with a matching sha256, and confirms no
excluded file is present. Edit any copied file and check fails
with exit 1. That is how a teammate who receives the fixture
can tell it is the same tree you built.

## Step 4: the override, and why it is loud

```sh
ghostfixture build examples/demo_project examples/demo_bundle \
    -o /tmp/demo-fixture-with-keys --include-flagged
```

Now keys.py is copied, but the manifest still records that it
was flagged and that it was included by override. There is no
quiet way to include a flagged file.
