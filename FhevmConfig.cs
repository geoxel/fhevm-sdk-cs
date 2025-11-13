namespace FhevmSDK;

public abstract class FhevmConfig
{
    // DECRYPTION_ADDRESS (Gateway chain)
    public abstract string VerifyingContractAddress { get; }

    // INPUT_VERIFICATION_ADDRESS (Gateway chain)
    public abstract string VerifyingContractAddressInputVerification { get; }

    // ACL_CONTRACT_ADDRESS (FHEVM Host chain)
    public abstract string AclContractAddress { get; }

    // KMS_VERIFIER_CONTRACT_ADDRESS (FHEVM Host chain)
    public abstract string KmsContractAddress { get; }

    // INPUT_VERIFIER_CONTRACT_ADDRESS (FHEVM Host chain)
    public abstract string InputVerifierContractAddress { get; }

    // FHEVM Host chain id
    public abstract ulong ChainId { get; }

    // Gateway chain id
    public abstract ulong GatewayChainId { get; }

    public abstract string RelayerUrl { get; }

    public abstract string InfuraUrl { get; }
}
