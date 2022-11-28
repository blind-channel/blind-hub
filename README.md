# Prerequisite
Please install `llvm`, `bison`, `libgmp3-dev` and `libpari-dev` for the benchmarking.

# Blind Channel and Blind Hub
To benchmark the blind hub + blind channel, run
```bash
cd blind-core
tar xJf circuit.tar.xz
cargo test -p blind-core --release zkgc::tests::test_zk_split_final -- --exact --test-threads=1 --nocapture
```

Note: the original [class group](https://github.com/ZenGo-X/class) doesn't work properly with multithreading test cases. Although we made substitute of class group compose and exp functions, it should be better to use the `--test-threads=1` to prevent other failures.

# Supplementary material (full version)
[supplementary material](BlindHub_GitHub.pdf)
