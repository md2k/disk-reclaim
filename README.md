# disk-reclaim

`reclaim` finds disk space you can safely get back, then lets you pick what to clean in a terminal UI.
It looks for stale build folders, tool caches, old tool versions, browser leftovers, Docker junk and
Time Machine local snapshots. Nothing is deleted until you confirm.

Python 3.9+, standard library only. Built for macOS; the generic parts also work on Linux.

## Install

```sh
git clone https://github.com/md2k/disk-reclaim.git
cd disk-reclaim
make install        # links ~/bin/reclaim (PREFIX=... to change)
```

## Run

```sh
reclaim             # scan, then choose in the picker
reclaim --dry-run   # scan and print a report, never deletes
sudo reclaim        # include folders your user can't read
```

See [docs/usage.md](docs/usage.md) for what it looks for, the safety rules, options and keys.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
