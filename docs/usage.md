# Using reclaim

## What it looks for

| Category | Where | Selected by default | How it comes back |
|---|---|---|---|
| `.terraform`, `.terragrunt-cache` | under `--root` | if unused for `--older-than` days | `terraform init` (+ `workspace select`) |
| `node_modules` | next to a `package.json` | same | `npm` / `yarn` / `pnpm install` |
| python venvs (`.venv`, `venv`) | folders with a `pyvenv.cfg` | same | recreate the venv |
| `target` | next to `Cargo.toml` / `pom.xml` | same | `cargo build` / `mvn package` |
| `.next`, `.nuxt`, `__pycache__` | under `--root` | same | the next build |
| `build`, `dist` | next to a project file (`Makefile`, `go.mod`, …) | never: review | re-run the build |
| big files | under `--root`, at least `--big-file-gb` | never: review | they don't |
| tool caches | Go, npm, yarn, pip, Homebrew, Playwright, VS Code updater | no | downloaded or rebuilt on next use |
| terraform versions | `~/.terraform.versions` (tfswitch) | if unused 90 days | tfswitch downloads them again |
| browser code-sign clones | your temp folder (macOS) | orphaned ones | the running browser keeps its own |
| docker | `docker system df` | no | rebuild or pull again |
| Time Machine local snapshots | `tmutil` (macOS) | no | they don't; your backup disk keeps its copies |

"Unused" is the newest access or change time of any file inside, so a `.terraform` folder that was
initialised months ago but planned yesterday counts as used yesterday.

Browser code-sign clones: Chrome-family browsers copy their own app into your temp folder at launch so a
background update can't break the running browser. They should delete the copy when they quit. A crash,
force-quit or restart with the browser open leaves it behind, about 1.5 GB each.

## Item states

| State | Colour | Meaning |
|---|---|---|
| preselect | green when selected | safe, and unused long enough to be selected by default |
| optional | plain | safe, but recent or costly to get back; off by default |
| review | yellow | may hold real files; off by default, check before selecting |
| protected | red | in use, active, or not yet backed up; cannot be selected |

Examples of protected items: the browser clone a running browser has open, the terraform binary `terraform`
points at, a snapshot newer than your last completed backup or in use by a running backup, Docker volumes.

## Safety rules

- Nothing is deleted without a confirmation that lists what goes and which commands run.
- Deletions are permanent (not to the Trash).
- Right before each deletion the path is checked again: it must still exist, must not be or go through a
  symlink, must sit inside the folder it was found in, must keep its name, and must not be a top-level folder.
- Caches with their own clean command are cleaned with that command (`go clean -cache`, `brew cleanup -s`, …).
- The walk never enters `.git`, `node_modules`, `site-packages`, app bundles or media libraries, other file
  systems, the Go module cache, or hidden folders and `~/Library` directly under your home folder.

## Permissions

Folders the scan can't read are counted and reported after the scan:

- **permission denied**: run with `sudo` to include them. The picker offers to re-run itself with sudo.
- **blocked by macOS privacy protection**: sudo doesn't help. Give your terminal Full Disk Access in
  System Settings > Privacy & Security.

Under sudo, reclaim still works on your files: it uses your home folder, and runs `go`, `npm`, `brew` and
`docker` as you.

## Options

```
--root DIR        where to look for project leftovers and big files (repeatable; default: home folder)
--older-than N    preselect project leftovers unused for more than N days (default 7)
--big-file-gb N   list files of at least N GB for review (default 1)
--no-big-files    skip the big-file listing
--dry-run         scan and print a report; never deletes
--json            with --dry-run: the report as JSON
--limit N         with --dry-run: items per category (0 = all, default 10)
```

## Keys

| Key | Categories screen | Inside a category |
|---|---|---|
| ↑ ↓, j k, PgUp PgDn, g G | move | move |
| space | select the category's safe items | toggle the item and move down |
| a | select all safe items everywhere | select every selectable item, review included |
| → or Enter | open the category | |
| ← or Esc | | back to categories |
| s | | sort by size, age or name |
| c | clean the selection | clean the selection |
| q | quit | quit |

## Notes

- Freed space can look stuck when Time Machine local snapshots exist: they hold files deleted since they were
  taken. After cleaning, reclaim says so; delete the snapshots covered by a completed backup, or wait for
  macOS to drop them (24 hours, or sooner when space runs low).
- Docker Desktop may take a while to shrink its disk image after a prune.
