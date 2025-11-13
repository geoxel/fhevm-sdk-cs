using System.Text.Json.Serialization;

namespace RelayerSDK;

public sealed class HandleContractPair
{
    [JsonPropertyName("handle")]
    public required string Handle { get; set; }

    [JsonPropertyName("contractAddress")]
    public required string ContractAddress { get; set; }
}
