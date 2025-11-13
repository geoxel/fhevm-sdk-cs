namespace FhevmSDK;

public sealed class Config
{
    public required string FHECounterContractAddress { get; set; }

    public required string UserAddress { get; set; }
    
    public string? EthPrivateKey { get; set; }
    public string? InfuraApiKey { get; set; }
}
