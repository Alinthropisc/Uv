## Contributing to uv

uv is always looking for contributors. Whether that's spelling mistakes or major changes, your help is **wanted** and welcomed here.

Before contributing, read our [code of conduct](CODE_OF_CONDUCT.md).

TL;DR: if you abuse members of our community you will be **perma-banned** with no warnings.

uv has 2 major labels for GitHub issues you should look at:

- **Good First Issue** — for newcomers to open source
- **Help Wanted** — not for newcomers, but we could still use help

If you want to contribute, solve the issue or comment on it for help.

The flow for contributing:

1. Fork the repo
2. Make changes
3. Open a pull request

## Development Environment

To ease contribution to uv, you can use the `contributing.Dockerfile` to create a Docker image ready to build and test uv.

Build the image:

```bash
you@home:~/uv$ docker build -t uv_contributing -f contributing.Dockerfile .
```

Run the container with a volume:

```bash
you@home:~/uv$ docker run -ti --rm -v "$PWD":/uv -w /uv uv_contributing bash
```

Inside the container, build and run:

```bash
root@container:/uv# cargo build
root@container:/uv# cargo run -- -b 2000 -t 5000 -a 127.0.0.1
```

Format, lint, and test:

```bash
root@container:/uv# cargo fmt
root@container:/uv# cargo clippy
root@container:/uv# cargo test
```

## TODO Items

uv has some `// TODO` comments in the codebase. These are mostly for the core team but contributions are welcome.

If you have feature suggestions or bug reports, open a GitHub issue.
