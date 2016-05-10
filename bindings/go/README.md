
= Build

```
env CGO_LDFLAGS="-L../../../build/llvm/lib/"
env CGO_CFLAGS="-I../../../include/keystone/"
```


= Test

```
env DYLD_LIBRARY_PATH=$(pwd)/../../../build/llvm/lib/ go test
```
