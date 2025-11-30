namespace FhevmSDK;

public sealed class FhevmSepoliaConfig : FhevmConfig
{
    // cf. https://docs.zama.org/protocol/solidity-guides/smart-contract/configure/contract_addresses

    public override string VerifyingContractAddress => "0x5D8BD78e2ea6bbE41f26dFe9fdaEAa349e077478";
    public override string VerifyingContractAddressInputVerification => "0x483b9dE06E4E4C7D35CCf5837A1668487406D955";
    public override string AclContractAddress => "0xf0Ffdc93b7E186bC2f8CB3dAA75D86d1930A433D";
    public override string KmsContractAddress => "0xbE0E383937d564D7FF0BC3b46c51f0bF8d5C311A";
    public override string InputVerifierContractAddress => "0xBBC1fFCdc7C316aAAd72E807D9b0272BE8F84DA0";
    public override ulong ChainId => 11155111;
    public override ulong GatewayChainId => 10901; // (42 << 8) + 149
    public override string RelayerUrl => "https://relayer.testnet.zama.org";
    public override string InfuraUrl => "https://sepolia.infura.io/v3";
}
