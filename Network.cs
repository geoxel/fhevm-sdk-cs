using Fhe;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.XPath;

namespace RelayerSDK;

public sealed class Network : IDisposable
{
    private static ConcurrentDictionary<string, Result> keyurlCache = new ConcurrentDictionary<string, Result>();

    public class Result : IDisposable
    {
        public required FheCompactPublicKey PublicKey { get; init; }
        public required string PublicKeyId { get; init; }

        // 2048
        public required FheCompactPkeCrs PublicParams { get; init; }
        public required string PublicParamsId { get; init; }

        public void Dispose()
        {
            PublicKey.Dispose();
            PublicParams.Dispose();
        }
    }

    public void Dispose()
    {
        foreach (var r in keyurlCache.Values)
            r.Dispose();

        keyurlCache.Clear();
    }

    public async Task<Result> GetKeysFromRelayer(string url, string? publicKeyId)
    {
        if (keyurlCache.TryGetValue(url, out Result cachedResult))
        {
            return cachedResult;
        }

        RelayerKeys relayerKeys =
            await RelayerKeys.ReadFromUrl(url + "/v1/keyurl")
            ?? throw new InvalidOperationException();

        string pubKeyUrl;

        // If no publicKeyId is provided, use the first one
        // Warning: if there are multiple keys available, the first one will most likely never be the
        // same between several calls (fetching the infos is non-deterministic)
        if (publicKeyId == null)
        {
            RelayerKeys.FhePublicKey fhePublicKey = relayerKeys.Response.FheKeyInfo[0].FhePublicKey;

            pubKeyUrl = fhePublicKey.Urls[0];
            publicKeyId = fhePublicKey.DataId;
        }
        else
        {
            // If a publicKeyId is provided, get the corresponding info
            RelayerKeys.FheKeyInfo keyInfo =
                relayerKeys.Response.FheKeyInfo.FirstOrDefault(fki => fki.FhePublicKey.DataId == publicKeyId)
                ?? throw new InvalidDataException($"Could not find FHE key info with data_id ${publicKeyId}");

            // TODO: Get a given party's public key url instead of the first one
            pubKeyUrl = keyInfo.FhePublicKey.Urls[0];
        }

        using HttpClient client = new();
        byte[] publicKey = await client.GetByteArrayAsync(pubKeyUrl);

        string publicParamsUrl = relayerKeys.Response.Crs["2048"].Urls[0];
        string publicParamsId = relayerKeys.Response.Crs["2048"].DataId;

        byte[] publicParams2048 = await client.GetByteArrayAsync(publicParamsUrl);

        const ulong SERIALIZED_SIZE_LIMIT_PK = 1024 * 1024 * 512;
        FheCompactPublicKey pub_key = FheCompactPublicKey.Deserialize(publicKey, SERIALIZED_SIZE_LIMIT_PK);

        const ulong SERIALIZED_SIZE_LIMIT_CRS = 1024 * 1024 * 512;
        FheCompactPkeCrs crs = FheCompactPkeCrs.Deserialize(publicParams2048, SERIALIZED_SIZE_LIMIT_CRS);

        Result result = new()
        {
            PublicKey = pub_key,
            PublicKeyId = publicKeyId,

            // 2048
            PublicParams = crs,
            PublicParamsId = publicParamsId,
        };

        keyurlCache[url] = result;
        return result;
    }
}
