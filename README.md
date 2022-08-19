# Blind Channel and Blind Hub
To benchmark the blind hub + blind channel, run
```
cargo test -p blind-core -- hub::tests::test_channel_hub_reduced --exact --test-threads=1
```

Note: the original [class group](https://github.com/ZenGo-X/class) doesn't work properly with multithreading test cases. Although we made substitute of class group compose and exp functions, it should be better to use the `--test-threads=1` to prevent other failures.
