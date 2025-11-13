using Fhe;
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
            // Note that the hex strings returned by the relayer do have have the 0x prefix
            if (h != rh)
                throw new InvalidOperationException($"Incorrect handle: (expected: {h}) != (received: {rh})");
        });

        /*
        TODO

        //const signatures: string[] = json.response.signatures;

        // verify signatures for inputs:
        const domain = {
          name: 'InputVerification',
          version: '1',
          chainId: fhevmConfig.GatewayChainId,
          verifyingContract: fhevmConfig.VerifyingContractAddressInputVerification,
        };
        const types = {
          CiphertextVerification: [
            { name: 'ctHandles', type: 'bytes32[]' },
            { name: 'userAddress', type: 'address' },
            { name: 'contractAddress', type: 'address' },
            { name: 'contractChainId', type: 'uint256' },
            { name: 'extraData', type: 'bytes' },
          ],
        };

        const recoveredAddresses = signatures.map((signature: string) => {
          const sig = Helpers.Ensure0xPrefix(signature);
          const recoveredAddress = ethers.verifyTypedData(
            domain,
            types,
            {
              ctHandles: handles,
              userAddress,
              contractAddress,
              contractChainId: fhevmConfig.ChainId,
              defaultExtraData,
            },
            sig,
          );
          return recoveredAddress;
        });

        if (!Helpers.IsThresholdReached(recoveredAddresses, _kmsSigcoprocessorSigners, _coprocessorSignersThreshold))
            throw new InvalidOperationException("Coprocessor signers threshold is not reached");
        */

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
