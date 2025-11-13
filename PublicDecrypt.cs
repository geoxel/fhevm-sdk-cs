using Nethereum.Util;
using Nethereum.ABI;
using Nethereum.ABI.FunctionEncoding;
using Nethereum.ABI.Model;
using FhevmSDK.Tools;
using FhevmSDK.Tools.Json;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Runtime.CompilerServices;

namespace FhevmSDK;

#if ___NOT_FINISHED___

public sealed class PublicDecrypt : Decrypt
{
    private readonly ServerIdAddr[] _indexedKmsSigners;
    private readonly HashSet<string> _kmsSigners;
    private readonly int _thresholdSignerCount;
    private readonly string _eip712Domain_json;
    private readonly string _verifyingContractAddress;
    private readonly string _aclContractAddress;
    private readonly string _relayerUrl;

    private readonly static JsonSerializerOptions json_serialization_options = new()
    {
        Converters = { new ByteArrayAsNumbersJsonConverter() }
    };

    public PublicDecrypt(
        string[] kmsSigners,
        int gatewayChainId,
        string verifyingContractAddress,
        string aclContractAddress,
        string relayerUrl)
    {
        _kmsSigners = kmsSigners.ToHashSet();

        // assume the KMS Signers have the correct order
        _indexedKmsSigners =
            Enumerable.Range(1, kmsSigners.Length)
            .Zip(kmsSigners, (index, signer) => ServerIdAddr.Create(index, signer))
            .ToArray();

        // TODO: not sure - BE or LE ?
        byte[] chainIdArrayBE = new byte[32];
        BinaryPrimitives.WriteInt32BigEndian(chainIdArrayBE.AsSpan(start: 28), gatewayChainId);

        Eip712DomainMsg eip712Domain = new()
        {
            name = "Decryption",
            version = "1",
            chain_id = chainIdArrayBE,
            verifying_contract = verifyingContractAddress,
            salt = null,
        };

        _eip712Domain_json = JsonSerializer.Serialize(eip712Domain, json_serialization_options);

        _verifyingContractAddress = verifyingContractAddress;
        _aclContractAddress = aclContractAddress;
        _relayerUrl = relayerUrl;
    }

    protected override void DisposeManagedResources()
    {
        _indexedKmsSigners.ForEach(s => s.Dispose());
    }

    private bool IsThresholdReached(string[] recoveredAddresses) =>
        Helpers.IsThresholdReached(recoveredAddresses, _kmsSigners, _thresholdSignerCount);

    private bool IsThresholdReached(string[] recoveredAddresses)
    {
        string duplicatedAddress =
            recoveredAddresses
            .GroupBy(a => a)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .FirstOrDefault();

        if (duplicatedAddress != null)
            throw new InvalidDataException($"Duplicate KMS signer address found: {duplicatedAddress} appears multiple times in recovered addresses");

        string unknownRecoveredAddress = recoveredAddresses.FirstOrDefault(ra => !_kmsSigners.Contains(ra));
        if (unknownRecoveredAddress != null)
            throw new InvalidDataException($"Invalid address found: {unknownRecoveredAddress} is not in the list of KMS signers");

        return recoveredAddresses.Length >= _thresholdSignerCount;
    }

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

    private static Dictionary<string, object> DeserializeDecryptedResult(string[] handles, string decryptedResult)
    {
        List<FheValueType> typesList = handles.Select(h => GetValueTypeFromHandle(h)).ToList();

        string restoredEncoded =
            "0x"
            + new string('0', 2 * 32) // dummy requestID (ignored)
            + decryptedResult.Substring(2)
            + new string('0', 2 * 32); // dummy empty bytes[] length (ignored)

        // all types are valid because this was supposedly checked already inside the `checkEncryptedBits` function
        List<string> abiTypes = typesList.Select(t => CiphertextType[t]).ToList();

        var decoder = new ParameterDecoder();
        List<ParameterOutput> outputs =
            decoder.DecodeDefaultData(
                restoredEncoded,
                new[] { new Parameter("uint256", "a0") }
                    .Concat(abiTypes.Select(t => new Parameter(t, "n")))
                    .Concat([new Parameter("bytes[]", "an")])
                    .ToArray()
                );

        return
            Enumerable.Range(0, handles.Length)
            .Zip(handles, (i, h) => new { i = i, h = h })
            .ToDictionary(o => o.h, o => outputs[1 + o.i].Result);
    }

    // https://github.com/zama-ai/fhevm-relayer/blob/96151ef300f787658c5fbaf1b4471263160032d5/src/http/public_decrypt_http_listener.rs#L19
    private class RelayerPublicDecryptPayload
    {
        public required string[] ciphertextHandles { get; set; }
        public required string extraData { get; set; }
    }

    public async Task<Dictionary<string, object>> Decrypt(string[] _handles)
    {
        string[] handles = _handles.Select(h => Helpers.Ensure0xPrefix(h)).ToArray();

        // const acl = new ethers.Contract(aclContractAddress, aclABI, provider);
        //   _handles = await Promise.all(
        //     _handles.map(async (_handle) => {
        //       const isAllowedForDecryption = await acl.isAllowedForDecryption(handle);
        //       if (!isAllowedForDecryption) 
        //         throw new Error($"Handle {handle} is not allowed for public decryption!");

        //       return handle;
        //     }),
        //   );

        // check 2048 bits limit
        CheckEncryptedBits(handles);

        const string DefaultExtraData = "0x00";

        RelayerPublicDecryptPayload payload = new()
        {
            ciphertextHandles = handles,
            extraData = DefaultExtraData,
        };

        using HttpClient httpClient = new();
        string pubKeyUrl = $"{_relayerUrl}/v1/public-decrypt";
        string payload_json = JsonSerializer.Serialize(payload);
        var content = new StringContent(payload_json, Encoding.UTF8, "application/json");
        using HttpResponseMessage response = await httpClient.PostAsync(pubKeyUrl, content);
        response.EnsureSuccessStatusCode(); // throw if not 2xx

        /*
            // verify signatures on decryption:
            const domain = {
              name: 'Decryption',
              version: '1',
              chainId: gatewayChainId,
              verifyingContract: verifyingContractAddress,
            };
            const types = {
              PublicDecryptVerification: [
                { name: 'ctHandles', type: 'bytes32[]' },
                { name: 'decryptedResult', type: 'bytes' },
                { name: 'extraData', type: 'bytes' },
              ],
            };

            const result = json.response[0];
            string decryptedResult = Helpers.Ensure0xPrefix() result.decrypted_value);

            const signatures = result.signatures;
            const signedExtraData = '0x';

            const recoveredAddresses = signatures.map((signature: string) => {
              const sig = signature.startsWith('0x') ? signature : `0x${signature}`;
              const recoveredAddress = ethers.verifyTypedData(
                domain,
                types,
                { ctHandles: handles, decryptedResult, extraData: signedExtraData },
                sig,
              );
              return recoveredAddress;
            });


        bool thresholdReached = IsThresholdReached(recoveredAddresses);
        if (!thresholdReached)
            throw new InvalidOperationException("KMS signers threshold is not reached");

        return DeserializeDecryptedResult(handles, decryptedResult);

        */

        return null;
    }
}

#endif // ___NOT_FINISHED___
