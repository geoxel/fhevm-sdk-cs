using Fhe;
using FhevmSDK.Tools;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FhevmSDK;

public sealed class CompactPublicKeyInfo
{
    public required CompactPublicKey PublicKey { get; init; }
    public required string PublicKeyId { get; init; }
}

public sealed class PublicParamsInfo
{
    public required CompactPkeCrs PublicParams { get; init; }
    public required string PublicParamsId { get; init; }
}

public sealed class FhevmKeys : IDisposable
{
    private readonly ConcurrentDictionary<string, Keys> keyurlCache = new();

    public class Keys : IDisposable
    {
        public required CompactPublicKeyInfo CompactPublicKeyInfo { get; init; }

        // 2048
        public required PublicParamsInfo PublicParamsInfo { get; init; }

        public void Dispose()
        {
            CompactPublicKeyInfo.PublicKey.Dispose();
            PublicParamsInfo.PublicParams.Dispose();
        }
    }

    private static class Json
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

        public class Response
        {
            [JsonPropertyName("fhe_key_info")]
            public required FheKeyInfo[] FheKeyInfo { get; set; }

            [JsonPropertyName("crs")]
            public required Dictionary<string, FhePublicKey> Crs { get; set; }
        }

        public sealed class Container
        {
            [JsonPropertyName("response")]
            public required Response Response { get; set; }
        }
    }

    public void Dispose()
    {
        keyurlCache.Values.ForEach(v => v.Dispose());

        keyurlCache.Clear();
    }

    public async Task<Keys> GetOrDownload(string relayerUrl, string? publicKeyId = null)
    {
        if (keyurlCache.TryGetValue(relayerUrl, out Keys? cachedKeys))
            return cachedKeys;

        using HttpClient client = new();
        string json = await client.GetStringAsync($"{relayerUrl}/v1/keyurl");

        Json.Response fhevmKeys =
            JsonSerializer.Deserialize<Json.Container>(json)?.Response
            ?? throw new InvalidOperationException();

        string pubKeyUrl;

        // If no publicKeyId is provided, use the first one
        // Warning: if there are multiple keys available, the first one will most likely never be the
        // same between several calls (fetching the infos is non-deterministic)
        if (publicKeyId == null)
        {
            Json.FhePublicKey fhePublicKey = fhevmKeys.FheKeyInfo[0].FhePublicKey;

            pubKeyUrl = fhePublicKey.Urls[0];
            publicKeyId = fhePublicKey.DataId;
        }
        else
        {
            // If a publicKeyId is provided, get the corresponding info
            Json.FheKeyInfo keyInfo =
                fhevmKeys.FheKeyInfo.FirstOrDefault(fki => fki.FhePublicKey.DataId == publicKeyId)
                ?? throw new InvalidDataException($"Could not find FHE key info with data_id {publicKeyId}");

            // TODO: Get a given party's public key url instead of the first one
            pubKeyUrl = keyInfo.FhePublicKey.Urls[0];
        }

        byte[] serializedPublicKey = await client.GetByteArrayAsync(pubKeyUrl);

        string publicParamsUrl = fhevmKeys.Crs["2048"].Urls[0];
        string publicParamsId = fhevmKeys.Crs["2048"].DataId;

        byte[] publicParams2048 = await client.GetByteArrayAsync(publicParamsUrl);

        CompactPublicKey? publicKey = null;
        CompactPkeCrs? crs = null;

        try
        {
            const ulong SERIALIZED_SIZE_LIMIT_PK = 1024 * 1024 * 512;
            publicKey = CompactPublicKey.SafeDeserialize(serializedPublicKey, SERIALIZED_SIZE_LIMIT_PK);

            const ulong SERIALIZED_SIZE_LIMIT_CRS = 1024 * 1024 * 512;
            crs = CompactPkeCrs.SafeDeserialize(publicParams2048, SERIALIZED_SIZE_LIMIT_CRS);

            Keys keys = new()
            {
                CompactPublicKeyInfo = new()
                {
                    PublicKey = publicKey,
                    PublicKeyId = publicKeyId,
                },

                // 2048
                PublicParamsInfo = new()
                {
                    PublicParams = crs,
                    PublicParamsId = publicParamsId,
                },
            };

            Keys addedKeys = keyurlCache.GetOrAdd(relayerUrl, keys);
            if (addedKeys == keys)
            {
                publicKey = null;
                crs = null;
            }

            return addedKeys;
        }
        finally
        {
            crs?.Dispose();
            publicKey?.Dispose();
        }
    }
}
