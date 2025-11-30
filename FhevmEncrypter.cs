using Fhe;
using Nethereum.ABI.EIP712;
using Nethereum.Signer;
using Nethereum.Signer.EIP712;
using Nethereum.Util;
using Nethermind.Int256; // https://github.com/NethermindEth/int256/tree/main
using FhevmSDK.Tools;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FhevmSDK;

public sealed class FhevmEncrypter
{
    // https://github.com/zama-ai/fhevm-relayer/blob/96151ef300f787658c5fbaf1b4471263160032d5/src/http/input_http_listener.rs#L17
    private sealed class FhevmInputProofPayload
    {
        // Hex encoded uint256 string without prefix
        public required string contractChainId { get; init; }
        // Hex encoded address with 0x prefix.
        public required string contractAddress { get; init; }
        // Hex encoded address with 0x prefix.
        public required string userAddress { get; init; }
        // List of hex encoded binary proof without 0x prefix
        public required string ciphertextWithInputVerification { get; init; }
        // Hex encoded bytes with 0x prefix. Default: 0x00
        public required string extraData { get; init; }
    }

    private static class Json
    {
        public class Response
        {
            [JsonPropertyName("handles")]
            public required string[] Handles { get; set; }

            [JsonPropertyName("signatures")]
            public required string[] Signatures { get; set; }
        }

        public sealed class Container
        {
            [JsonPropertyName("response")]
            public required Response Response { get; set; }
        }
    }

    public static async Task<FhevmEncryptedValues> Encrypt(
        FhevmConfig fhevmConfig,
        EncryptedValuesBuilder builder,
        PublicParamsInfo publicParams,
        IReadOnlyList<string> coprocessorSigners,
        int coprocessorSignersThreshold,
        string contractAddress,
        string userAddress)
    {
        if (!AddressHelper.IsAddress(contractAddress))
            throw new InvalidDataException("Invalid contract address");

        if (!AddressHelper.IsAddress(userAddress))
            throw new InvalidDataException("Invalid user address");

        const string defaultExtraData = "0x00";
        byte[] ciphertext = builder.Encrypt(
            publicParams,
            fhevmConfig.AclContractAddress,
            fhevmConfig.ChainId,
            contractAddress,
            userAddress);

        FhevmInputProofPayload payload = new()
        {
            contractChainId = $"0x{fhevmConfig.ChainId:X}".ToLower(),
            contractAddress = AddressHelper.GetChecksumAddress(contractAddress),
            userAddress = AddressHelper.GetChecksumAddress(userAddress),
            ciphertextWithInputVerification = Convert.ToHexString(ciphertext),
            extraData = defaultExtraData,
        };

        using HttpClient httpClient = new();

        string pubKeyUrl = $"{fhevmConfig.RelayerUrl}/v1/input-proof";
        string payload_json = JsonSerializer.Serialize(payload);

        using StringContent content = new(payload_json, Encoding.UTF8, "application/json");
        using HttpResponseMessage response = await httpClient.PostAsync(pubKeyUrl, content);
        response.EnsureSuccessStatusCode(); // throw if not 2xx

        string json = await response.Content.ReadAsStringAsync();

        Json.Response resp =
            JsonSerializer.Deserialize<Json.Container>(json)?.Response
            ?? throw new InvalidOperationException();

        string[] handles = HandleHelper.CreateHandles(
            builder.GetValueTypes(),
            ciphertext,
            fhevmConfig.AclContractAddress,
            fhevmConfig.ChainId,
            ciphertextVersion: 0);

        if (handles.Length != resp.Handles.Length)
            throw new InvalidOperationException($"Incorrect Handles list sizes: (expected: {handles.Length}) != (received: {resp.Handles.Length})");

        handles.Zip(resp.Handles).ForEach(o =>
        {
            string h = o.First;
            string rh = o.Second;
            if (h != rh)
                throw new InvalidOperationException($"Incorrect handle: (expected: {h}) != (received: {rh})");
        });

        var typedData = new TypedData<Domain>
        {
            Domain = new Domain
            {
                Name = "InputVerification",
                Version = "1",
                ChainId = fhevmConfig.GatewayChainId,
                VerifyingContract = fhevmConfig.VerifyingContractAddressInputVerification,
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
                ["CiphertextVerification"] =
                [
                    new MemberDescription { Name = "ctHandles", Type = "bytes32[]" },
                    new MemberDescription { Name = "userAddress", Type = "address" },
                    new MemberDescription { Name = "contractAddress", Type = "address" },
                    new MemberDescription { Name = "contractChainId", Type = "uint256" },
                    new MemberDescription { Name = "extraData", Type = "bytes" },
                ],
            },
            PrimaryType = "CiphertextVerification",
            Message =
            [
                new MemberValue { TypeName = "bytes32[]", Value = handles.Select(h => Convert.FromHexString(h[2..])).ToArray() }, // ctHandles
                new MemberValue { TypeName = "address", Value = userAddress }, // userAddress
                new MemberValue { TypeName = "address", Value = contractAddress }, // contractAddress
                new MemberValue { TypeName = "uint256", Value = fhevmConfig.ChainId }, // contractChainId
                new MemberValue { TypeName = "bytes", Value = defaultExtraData }, // extraData
            ],
        };

        var typedDataSigner = new Eip712TypedDataSigner();

        string[] recoveredAddresses =
            resp.Signatures
            .Select(signature => typedDataSigner.RecoverFromSignatureV4(typedData, signature))
            .ToArray();

        if (!Helpers.IsThresholdReached(recoveredAddresses, coprocessorSigners, coprocessorSignersThreshold))
            throw new InvalidOperationException("Coprocessor signers threshold is not reached");

        // inputProof is len(list_handles) + numCoprocessorSigners + list_handles + signatureCoprocessorSigners (1+1+NUM_HANDLES*32+65*numSigners)
        var inputProof = string.Concat(
        [
            $"{handles.Length:X2}",
            $"{resp.Signatures.Length:X2}",
            .. handles.Select(s => s[2..]), // removes the '0x' prefix from the "handle" strings
            .. resp.Signatures.Select(s => s[2..]), // removes the '0x' prefix from the "signature" strings
            defaultExtraData[2..],
        ]);

        return new FhevmEncryptedValues
        {
            Handles = handles,
            InputProof = inputProof,
        };
    }
}
