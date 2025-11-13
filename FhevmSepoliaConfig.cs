namespace RelayerSDK;

public sealed class FhevmSepoliaConfig : FhevmConfig
{
    // cf. https://docs.zama.org/protocol/solidity-guides/smart-contract/configure/contract_addresses

    public override string VerifyingContractAddress => "0xb6E160B1ff80D67Bfe90A85eE06Ce0A2613607D1";

    public override string VerifyingContractAddressInputVerification => "0x7048C39f048125eDa9d678AEbaDfB22F7900a29F";

    public override string AclContractAddress => "0x687820221192C5B662b25367F70076A37bc79b6c";

    public override string KmsContractAddress => "0x1364cBBf2cDF5032C47d8226a6f6FBD2AFCDacAC";

    public override string InputVerifierContractAddress => "0xbc91f3daD1A5F19F8390c400196e58073B6a0BC4";

    public override ulong ChainId => 11155111;

    public override ulong GatewayChainId => 55815; // (31 << 8) + 70

    public override string RelayerUrl => "https://relayer.testnet.zama.cloud";

    public override string InfuraUrl => "https://sepolia.infura.io/v3";
}
