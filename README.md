Building a .NET C# interop on the KMS library and do some relayer-sdk things in C#.

## Setup

Retrieve the TFHE repo and build it with the C API.
```bash
$ git clone https://github.com/zama-ai/tfhe-rs.git
$ cd tfhe-rs
$ RUSTFLAGS="-C target-cpu=native" cargo +nightly build --release --features=high-level-c-api -p tfhe
$ ls -lF target/release
$ cd ..
```
Retrieve this repo.
```bash
$ git clone https://github.com/geoxel/relayer-csharp.git
$ cd relayer-csharp
```
## Build
Build the modified KMS lib.
```bash
$ (cd kms/core/service/ ; cargo b --release --lib)
```
Adjustements have been made in:
```
kls/core/service/src/client/c_buffer.rs
kms/core/service/src/client/c_error.rs
kms/core/service/src/client/c_utils.rs
kms/core/service/src/client/client_c_api.rs
kms/core/service/src/client/mod.rs
```
TODO: use a kms-c-api feature.
## Testing
Run the .NET app:
```bash
$ dotnet run -c Release
Hi relayer.
private key len = 1640
6006000000000000443A670498232DDCCEB0C51E39B922A14B023E2349868CBA53...
public key len = 869
0300000000000000302E35000000000300000000000000302E3113000000000000...
Bye relayer.
```

*What a time to be alive!*
