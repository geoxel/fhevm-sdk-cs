using Fhe;
using Nethereum.Util;
using Nethereum.ABI;
using Nethereum.ABI.EIP712;
using Nethereum.ABI.FunctionEncoding;
using Nethereum.ABI.Model;
using Nethereum.Contracts;
using Nethereum.Signer.EIP712;
using FhevmSDK.Kms;
using FhevmSDK.Tools;
using FhevmSDK.Tools.Json;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.CompilerServices;

namespace FhevmSDK;

public sealed class PublicDecrypt : Decrypt
{
    private readonly Config _config;
    private readonly FhevmConfig _fhevmConfig;

    private readonly ServerIdAddr[] _indexedKmsSigners;
    private readonly string _eip712Domain_json;
    private readonly IReadOnlyList<string> _kmsSigners;
    private readonly int _kmsSignersThreshold;

    private readonly static JsonSerializerOptions _json_serialization_options = new()
    {
        Converters = { new ByteArrayAsNumbersJsonConverter() }
    };

    public PublicDecrypt(
        Config config,
        FhevmConfig fhevmConfig,
        IReadOnlyList<string> kmsSigners,
        int kmsSignersThreshold)
    {
        _config = config;
        _fhevmConfig = fhevmConfig;

        _kmsSigners = kmsSigners;
        _kmsSignersThreshold = kmsSignersThreshold;

        // assume the KMS Signers have the correct order
        _indexedKmsSigners =
            Enumerable.Range(1, kmsSigners.Count)
            .Zip(kmsSigners, (index, signer) => ServerIdAddr.Create(index, signer))
            .ToArray();

        // TODO: not sure, why not writing a BE uint64 at offset 24 ?
        byte[] chainIdArrayBE = new byte[32];
        BinaryPrimitives.WriteUInt32BigEndian(chainIdArrayBE.AsSpan(start: 28), (uint)_fhevmConfig.GatewayChainId);

        Eip712DomainMsg eip712Domain = new()
        {
            name = "Decryption",
            version = "1",
            chain_id = chainIdArrayBE,
            verifying_contract = fhevmConfig.VerifyingContractAddress,
            salt = null,
        };

        _eip712Domain_json = JsonSerializer.Serialize(eip712Domain, _json_serialization_options);
    }

    protected override void DisposeManagedResources()
    {
        _indexedKmsSigners.ForEach(s => s.Dispose());
    }

    private bool IsThresholdReached(string[] recoveredAddresses) =>
        Helpers.IsThresholdReached(recoveredAddresses, _kmsSigners, _kmsSignersThreshold);

    private static readonly Dictionary<FheValueType, string> CiphertextType = new()
    {
        { FheValueType.Bool, "bool" },
        { FheValueType.UInt8, "uint256" },
        { FheValueType.UInt16, "uint256" },
        { FheValueType.UInt32, "uint256" },
        { FheValueType.UInt64, "uint256" },
        { FheValueType.UInt128, "uint256" },
        { FheValueType.Address,"address" },
        { FheValueType.UInt256, "uint256" },
    };

    private static Dictionary<string, object> DeserializeClearValues(IReadOnlyList<string> handles, string decryptedResult)
    {
        string restoredEncoded =
            "0x"
            + new string('0', 2 * 32) // dummy requestID (ignored)
            + decryptedResult
            + new string('0', 2 * 32); // dummy empty bytes[] length (ignored)

        // all types are valid because this was supposedly checked already inside the `checkEncryptedBits` function
        List<FheValueType> types =
            handles
            .Select(h => HandleHelper.GetValueType(h))
            .ToList();

        var decoder = new ParameterDecoder();
        List<ParameterOutput> outputs =
            decoder.DecodeDefaultData(
                restoredEncoded,
                [
                    new Parameter("uint256", "a0"),
                    ..types.Select(t => new Parameter(CiphertextType[t], "n")),
                    new Parameter("bytes[]", "an")
                ]);

        return
            BuildDecryptedResults(
                handles,
                handles.Select(h => HandleHelper.GetValueType(h)).ToList(),
                outputs.Skip(1).Take(outputs.Count - 2).Select(o => (BigInteger)o.Result).ToList());
    }

    private static byte[] AbiEncodeClearValues(Dictionary<string, object> clearValues)
    {
        ABIValue[] abiValues =
            clearValues
            .Select(kv =>
            {
                string handle = kv.Key;
                FheValueType handleType = HandleHelper.GetValueType(handle);
                object clearTextValue = kv.Value;

                if (clearTextValue is bool clearBool)
                    clearTextValue = clearBool;

                string abiType = "uint256";
                object abiValue = handleType switch
                {
                    FheValueType.Address => $"0x{BigInteger.Parse((string)clearTextValue):X40}",
                    FheValueType.Bool => Convert.ToBoolean(clearTextValue),
                    FheValueType.UInt8 or
                    FheValueType.UInt16 or
                    FheValueType.UInt32 or
                    FheValueType.UInt64 or
                    FheValueType.UInt128 or
                    FheValueType.UInt256 => clearTextValue,
                    _ => throw new InvalidOperationException($"Unsupported Fhevm primitive type id: {handleType}")
                };

                return new ABIValue(abiType, abiValue);
            })
            .ToArray();

        ABIEncode abiEncode = new();
        return abiEncode.GetABIEncoded(abiValues);
    }
    /*
        private static string BuildDecryptionProof(IReadOnlyList<string> kmsSignatures, string extraData)
        {
            // Build the decryptionProof as numSigners + KMS signatures + extraData

            ABIEncodePacked encodePacked = new();

            byte[] packedNumSigners = encodePacked.GetABIEncodedPacked(
                new ABIValue("uint256", kmsSignatures.length)
            );

            byte[] packedSignatures = encodePacked.GetABIEncodedPacked(
                Enumerable.Range(0, kmsSignatures.Count).Select(_ => "bytes").ToArray(),
                kmsSignatures
            );

            return Helpers.To0xHexString(packedNumSigners.Concat(packedSignatures));
        }
    */
    private static class Json
    {
        // https://github.com/zama-ai/fhevm-relayer/blob/96151ef300f787658c5fbaf1b4471263160032d5/src/http/public_decrypt_http_listener.rs#L19
        public class RelayerPublicDecryptPayload
        {
            public required string[] ciphertextHandles { get; set; }
            public required string extraData { get; set; }
        }

        public class PublicDecryptionResponse
        {
            [JsonPropertyName("decrypted_value")]
            public required string DecryptedValue { get; set; }

            [JsonPropertyName("signatures")]
            public required string[] Signatures { get; set; }
        }

        public class Container
        {
            [JsonPropertyName("response")]
            public required PublicDecryptionResponse[] Response { get; set; }
        }
    }

    private const string _aclAbi =
    @"[
        {
            'constant': true,
            'inputs': [ { 'name': 'handle',  'type': 'bytes32' } ],
            'name': 'isAllowedForDecryption',
            'outputs': [ { 'name': '', 'type': 'bool' } ],
            'type': 'function'
        }
    ]";

    public async Task<Dictionary<string, object>> Decrypt(IReadOnlyList<string> _handles)
    {
        string[] handles = _handles.Select(Helpers.Ensure0xPrefix).ToArray();

        Contract contract = CounterClient.GetContract(_fhevmConfig.AclContractAddress, _aclAbi, _config, _fhevmConfig);
        Function isAllowedForDecryption_Function = contract.GetFunction("isAllowedForDecryption");

        foreach (string handle in handles)
        {
            bool isAllowedForDecryption = await isAllowedForDecryption_Function.CallAsync<bool>(Convert.FromHexString(handle[2..]));

            if (!isAllowedForDecryption)
                throw new InvalidOperationException($"Handle {handle} is not allowed for public decryption");
        }

        // check 2048 bits limit
        CheckEncryptedBits(handles);

        Json.RelayerPublicDecryptPayload payload = new()
        {
            ciphertextHandles = handles,
            extraData = "0x00",
        };

        using HttpClient httpClient = new();
        string pubKeyUrl = $"{_fhevmConfig.RelayerUrl}/v1/public-decrypt";
        string payload_json = JsonSerializer.Serialize(payload);
        var content = new StringContent(payload_json, Encoding.UTF8, "application/json");
        using HttpResponseMessage response = await httpClient.PostAsync(pubKeyUrl, content);

        //Console.WriteLine("RESP : " + await response.Content.ReadAsStringAsync());

        response.EnsureSuccessStatusCode(); // throw if not 2xx

        string resp_json = await response.Content.ReadAsStringAsync();
        Json.Container resp = JsonSerializer.Deserialize<Json.Container>(resp_json) ?? throw new InvalidDataException("Invalid response");

        Json.PublicDecryptionResponse result = resp.Response[0];

        var typedData = new TypedData<Domain>
        {
            Domain = new Domain
            {
                Name = "Decryption",
                Version = "1",
                ChainId = _fhevmConfig.GatewayChainId,
                VerifyingContract = _fhevmConfig.VerifyingContractAddress,
            },
            Types = new Dictionary<string, MemberDescription[]>
            {
                ["EIP712Domain"] =
                [
                    new MemberDescription { Name = "name", Type = "string" },
                    new MemberDescription { Name = "version", Type = "string" },
                    new MemberDescription { Name = "chainId", Type = "uint256" },
                    new MemberDescription { Name = "verifyingContract", Type = "address" },
                ],
                ["PublicDecryptVerification"] =
                [
                    new MemberDescription { Name = "ctHandles", Type = "bytes32[]" },
                    new MemberDescription { Name = "decryptedResult", Type = "bytes" },
                    new MemberDescription { Name = "extraData", Type = "bytes" },
                ],
            },
            PrimaryType = "PublicDecryptVerification",
            Message =
            [
                new MemberValue { TypeName = "bytes32[]", Value = handles.Select(h => Convert.FromHexString(h[2..])).ToArray() }, // ctHandles
                new MemberValue { TypeName = "bytes", Value = Convert.FromHexString(result.DecryptedValue) }, // decryptedResult
                new MemberValue { TypeName = "bytes", Value = "0x" }, // extraData
            ],
        };

        var typedDataSigner = new Eip712TypedDataSigner();

        List<string> recoveredAddresses =
            result.Signatures
            .Select(signature => typedDataSigner.RecoverFromSignatureV4(typedData, signature))
            .ToList();

        if (!Helpers.IsThresholdReached(recoveredAddresses, _kmsSigners, _kmsSignersThreshold))
            throw new InvalidOperationException("KMS signers threshold is not reached");

        Dictionary<string, object> clearValues = DeserializeClearValues(handles, result.DecryptedValue);

        //byte[] abiEncodedClearValues = AbiEncodeClearValues(clearValues);
        //Console.WriteLine(BuildDecryptionProof(result.DecryptedValue.Select(Helper.Ensure0xPrefix).ToArray()));

        return clearValues;

        /*
            const abiEnc = AbiEncodeClearValues(clearValues);
            const decryptionProof = buildDecryptionProof(
                kmsSignatures,
                signedExtraData,

            );

            return {
                clearValues,
            abiEncodedClearValues: abiEnc.abiEncodedClearValues,
            decryptionProof,
        };
        */
    }
}
