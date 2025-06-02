
## Usage

```
make build
make run # spawns shell
```

In container `$(pwd)/data` is mounted to `/data` and `$(pwd)/src` is mounted to `/src`:
```
time /ghidra/support/analyzeHeadless /data/out/ GhidraProject -scriptPath /src/ -postScript main.py +d /data/in/installd/ -deleteProject
```

To obtain the coverage for `installd`, the structure should look like this:
```
in/installd/
├── merged-cov.log
└── objs
    ├── installd
    └── liblogwrap.so
```
