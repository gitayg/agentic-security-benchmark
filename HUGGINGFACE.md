# Publishing the Hugging Face mirror

`scripts/export-hf.mjs` builds `dist/hf/` — one JSONL file per corpus and split, a dataset card with
the subset configuration, and copies of `LICENSE` and `NOTICE` — from the seven published corpora and
nothing else. `dist/` is gitignored. These steps are the owner's; nothing in this repository logs in
or uploads.

CLI syntax below is from the Hugging Face CLI guide
(<https://huggingface.co/docs/huggingface_hub/guides/cli>), where the command is `hf`.

## One-time setup

1. Create the organization **`moorai-dev`**: <https://huggingface.co/organizations/new>.
2. Create an access token with write access to `moorai-dev`: <https://huggingface.co/settings/tokens>.
3. Install the CLI (either one):
   ```bash
   curl -LsSf https://hf.co/cli/install.sh | bash
   pip install -U "huggingface_hub"
   ```
4. Log in and confirm the org is listed:
   ```bash
   hf auth login
   hf auth whoami        # the orgs: line must include moorai-dev
   ```

## Each release

From a clean checkout of `main`:

```bash
git fetch origin
node scripts/export-hf.mjs      # refuses to run if corpora/ differs from origin/main
node --test                     # includes test/export-hf.mjs
hf upload moorai-dev/agentic-security-benchmark dist/hf . --repo-type dataset \
  --commit-message "v$(node -p 'require("./package.json").version')"
```

`hf upload` creates the dataset repository if it does not exist. To create it
first instead: `hf repos create moorai-dev/agentic-security-benchmark --repo-type dataset`.

If a later export drops or renames a file, add `--delete="*"` to the upload so files no longer in
`dist/hf` are removed from the Hub repository.

Then open <https://huggingface.co/datasets/moorai-dev/agentic-security-benchmark> and check that the
Dataset Viewer shows the `all` subset first, with `attack` and `benign` splits.

## What the export refuses

The export list must be exactly the seven files in `corpora/`. A file outside that set, a filename
shaped like a locked held-out split (`*heldout*-test.json`, `*test-split*.json`, `locked/`), a
`split: "test"` row, or a lock-shaped top-level key stops the export before anything is written.
