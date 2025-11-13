<p align="center">
<img " width="422" height="88" alt="zama-csharp" src="https://github.com/user-attachments/assets/3a529c67-7ca3-4298-85a7-23fc070b257f" />
</p>



# What is C# FHEVM SDK ?

Here is a C# FHEVM SDK, that encrypts and decrypts FHE handles values on the Sepolia blockchain.

# Requirements

- A Rust environment is required: go to https://rust-lang.org/tools/install/ and install the Rust toolchain.

- .NET : go to https://dotnet.microsoft.com/en-us/download/dotnet/10.0 and install the **.NET SDK** (not the Runtime). The `dotnet` command must be in your `PATH`.

- Infura Key : go to the MetaMask website.

- Follow the https://docs.zama.org/protocol/solidity-guides/getting-started/setup tutorial and deploy a `FHECounter.sol` contract.

- To deploy a FHECounter, clone the https://github.com/zama-ai/fhevm-hardhat-template repository.

# How to install

## Step 1
 
Retrieve the forked TFHE repo and build it with the c-api feature. The fork just adds the "safe" serialization of `ProvenCompactCiphertextList`. (I lost so many hours figuring out that "safe serialization" was absolutely different from "serialization")
The branch commit is based on the tfhe-rs `release/1.3.x` branch.
```bash
$ git clone https://github.com/geoxel/tfhe-rs.git
$ cd tfhe-rs
$ git checkout geoxel/safe_serialization
$ RUSTFLAGS="-C target-cpu=native" cargo +nightly build --release --features=high-level-c-api,zk-pok -p tfhe
$ cd ..
```

## Step 2

Retrieve the forked KMS repo that includes the new c-api interop, enabled by the kms-c-api Rust feature.
The commit is based on the KMS `release/v0.11.x` branch.
```bash
$ git clone https://github.com/geoxel/kms.git
$ cd kms
$ git checkout geoxel/c_api
$ (cd core/service && RUSTFLAGS="-C target-cpu=native" cargo build --release --lib --features=kms-c-api)
$ cd ..
```

## Step 3

Finally, retrieve this repo.
```bash
$ git clone https://github.com/geoxel/fhevm-sdk-cs.git
$ cd fhevm-sdk-cs
```
# Run
The sample client has the following options:
```
Description:
  Simple FHECounter client app on Sepolia

Usage:
  dotnet run [command] [options]

Options:
  -?, -h, --help  Show help and usage information
  --version       Show version information

Commands:
  print-counter-handle   Print the FHE counter handle.
  decrypt-counter-value  Decrypt and print FHE counter value.
  increment              Increment counter.
  decrement              Decrement counter.
```
The deployed `FHECounter.sol` contract is:
```solidity
// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

/// @title A simple counter contract
contract Counter {
  uint32 private _count;

  /// @notice Returns the current count
  function getCount() external view returns (uint32) {
    return _count;
  }

  /// @notice Increments the counter by a specific value
  function increment(uint32 value) external {
    _count += value;
  }

  /// @notice Decrements the counter by a specific value
  function decrement(uint32 value) external {
    require(_count >= value, "Counter: cannot decrement below zero");
    _count -= value;
  }
}
```

You should have followed the https://docs.zama.org/protocol/solidity-guides/getting-started/setup tutorial and deployed a simple `Counter.sol` contract on the Sepolia blockchain.
The contract address has been set in `Config.json` as well as your user address. You can also set the ETH private key as well as the Infura API key in this file. (or not, in this case you have to enter them as shown below)

Let's print the current FHE Counter handle:
```bash
$ dotnet run print-counter-handle
Reading config from file Config.json...
Enter the ETH private key: ****************************************************************
Enter the Infura API key: ********************************
Retrieving FHECounter contract 0x1E585824420EeA85D0576f09Fcf3FfE896d07dAa...
Counter handle: 0x3da3331e03c1bbd69f1845b4b9d1a39e1b417a9f51ff0000000000aa36a70400 (encrypted type: UInt32)
```
Let's decrypt the counter value:
```bash
$ dotnet run decrypt-counter-value
Reading config from file Config.json...
Enter the ETH private key: ****************************************************************
Enter the Infura API key: ********************************
Retrieving FHECounter contract 0x1E585824420EeA85D0576f09Fcf3FfE896d07dAa...
Generating key pair...
Creating EIP-712 typed data...
Signing EIP-712 typed data...
EIP-712 signature: 0x14e451275532827ed2333b8843d0fe9a9a66c56d23ba72b2c3fb0718b72ec7947c4303b350c78ea294e83efd5889f8781c53d5573d1d41a916b8ce9cbfc85b411c
Retrieving KMS signers...
Decrypting handle...
Success:
Counter handle: 0x3da3331e03c1bbd69f1845b4b9d1a39e1b417a9f51ff0000000000aa36a70400 (encrypted type: UInt32)
Counter value : 24 (C# type: System.UInt32)```
```
Now let's retrieve one (1) from this FHE counter:
```bash
$ dotnet run decrement --value 1
Reading config from file Config.json...
Enter the ETH private key: ****************************************************************
Enter the Infura API key: ********************************
Retrieving keys from Zama server...
Encrypting input value (1)...
Encrypted input value handle: 0x2653ef8ab859b85596613ede1da016809c99461ecb000000000000aa36a70400
Encrypted input value proof: 01012653ef8ab859b85596613ede1da016809c99461ecb000000000000aa36a704005c82e7243cde65690fa5834f3dfc49cbb4aeff8d11f00f58108b806d5b36846068280e4f57c4c0dd5bb840d17b6bfdd8e7457b87ca2dd7ae4c499d41ebc6244b1b00
Retrieving FHECounter contract 0x1E585824420EeA85D0576f09Fcf3FfE896d07dAa...
Calling decrement() function...
Transaction hash: 0x6792828955e7a8afc4a70f766feca4bf38685bfc61192d6d937590e4ebf55fc4
Block number: 9623455
Gas used: 208393
New FHE Counter handle: 0xb5377b379a0060ebbf593dbc2c7a9d0deab053636eff0000000000aa36a70400
```
And let's decrypt and print the new value:
```bash
$ dotnet run decrypt-counter-value
Reading config from file Config.json...
Enter the ETH private key: ****************************************************************
Enter the Infura API key: ********************************
Retrieving FHECounter contract 0x1E585824420EeA85D0576f09Fcf3FfE896d07dAa...
Generating key pair...
Creating EIP-712 typed data...
Signing EIP-712 typed data...
EIP-712 signature: 0x85a3bc5a77e94b01b826202eecf82396d969092f8eba57143a508f07603ef7296cc030d30a897d02e4a1d29d5eb3d1d52c8d4b365f5667696856c76c44436a201c
Retrieving KMS signers...
Decrypting handle...
Success:
Counter handle: 0xb5377b379a0060ebbf593dbc2c7a9d0deab053636eff0000000000aa36a70400 (encrypted type: UInt32)
Counter value : 23 (C# type: System.UInt32)
```
Finally let's add back one (1) to the FHE counter:
```bash
$ dotnet run increment --value 1
Reading config from file Config.json...
Enter the ETH private key: ****************************************************************
Enter the Infura API key: ********************************
Retrieving keys from Zama server...
Encrypting input value (1)...
Encrypted input value handle: 0xf5e2e57e6586e35fa7532ecd98d3c44ea2c2623451000000000000aa36a70400
Encrypted input value proof: 0101f5e2e57e6586e35fa7532ecd98d3c44ea2c2623451000000000000aa36a70400b56d3b161118105da4f11d0af1812e2c6639d0b9c811602d1133ab8f01c36d8d16dbc58ed67fd59540630f18feea6dbb597374069c128031dc12b16978b724681c00
Retrieving FHECounter contract 0x1E585824420EeA85D0576f09Fcf3FfE896d07dAa...
Calling increment() function...
Transaction hash: 0x15637b0bb7e538896c6967c10c34f9e8494c642fa610dd8b0d1ae8e7cd9f778c
Block number: 9623468
Gas used: 208313
New FHE Counter handle: 0x41c58865b85819f0dc96bbd3f669a56d1506b7c379ff0000000000aa36a70400
```
And check back the counter value:
```bash
$ dotnet run decrypt-counter-value
Reading config from file Config.json...
Enter the ETH private key: ****************************************************************
Enter the Infura API key: ********************************
Retrieving FHECounter contract 0x1E585824420EeA85D0576f09Fcf3FfE896d07dAa...
Generating key pair...
Creating EIP-712 typed data...
Signing EIP-712 typed data...
EIP-712 signature: 0x3364aa91e31dc3c6ed361bbe86dbbda7afaa1c152faa22ff3a732bf9ef157f2309adcfb0d94bf6e0d4b92682cfe49c07684c863c034b94a934e1dd96f898af771b
Retrieving KMS signers...
Decrypting handle...
Success:
Counter handle: 0x41c58865b85819f0dc96bbd3f669a56d1506b7c379ff0000000000aa36a70400 (encrypted type: UInt32)
Counter value : 24 (C# type: System.UInt32)
```

*What a time to be alive!*
