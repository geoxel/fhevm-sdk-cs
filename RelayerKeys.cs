using System;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RelayerSDK;

/*
https://relayer.testnet.zama.cloud/v1/keyurl
Example:

{
    "response": {
        "fhe_key_info": [
            {
                "fhe_public_key": {
                    "data_id": "fhe-public-key-data-id",
                    "urls": [
                        "https://zama-zws-testnet-tkms-jpn6x.s3.eu-west-1.amazonaws.com/PUB-p1/PublicKey/8ca1dda263deedc8e9a61ed3e0ed48b6635aa35d98b85dff7d5f16c141cd708b"
                    ]
                }
            }
        ],
        "crs": {
            "2048": {
                "data_id": "crs-data-id",
                "urls": [
                    "https://zama-zws-testnet-tkms-jpn6x.s3.eu-west-1.amazonaws.com/PUB-p1/CRS/e4e2e9918e96eb7f3d02a01dc9c5d8cfb97e4b58cbfcce8cee4c3c0f011c27ee"
                ]
            }
        }
    }
}
*/

public sealed class RelayerKeys
{
    public class FhePublicKey
    {
        [JsonPropertyName("data_id")]
        public required string DataId { get; set; }

        [JsonPropertyName("urls")]
        public required string[] Urls { get; set; }
    }

    public class FheKeyInfo
    {
        [JsonPropertyName("fhe_public_key")]
        public required FhePublicKey FhePublicKey { get; set; }
    }

    public class RelayerKeysResponse
    {
        [JsonPropertyName("fhe_key_info")]
        public required FheKeyInfo[] FheKeyInfo { get; set; }

        [JsonPropertyName("crs")]
        public required Dictionary<string, FhePublicKey> Crs { get; set; }
    }

    [JsonPropertyName("response")]
    public required RelayerKeysResponse Response { get; set; }

    public static async Task<RelayerKeys?> ReadFromUrl(string url)
    {
        using HttpClient client = new();
        string json = await client.GetStringAsync(url);

        return JsonSerializer.Deserialize<RelayerKeys>(json);
    }
}
