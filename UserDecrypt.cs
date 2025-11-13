using Fhe;
using RelayerSDK.Kms;
using RelayerSDK.Tools;
using RelayerSDK.Tools.Json;
using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RelayerSDK;

public sealed class UserDecrypt : Decrypt
{
    private readonly FhevmConfig _fhevmConfig;
    private readonly ServerIdAddr[] _indexedKmsSigners;
    private readonly string _eip712Domain_json;

    private readonly static JsonSerializerOptions _json_serialization_options = new()
    {
        Converters = { new ByteArrayAsNumbersJsonConverter(), new BigIntegerConverter() }
    };

    public UserDecrypt(
        FhevmConfig fhevmConfig,
        IReadOnlyList<string> kmsSigners)
    {
        _fhevmConfig = fhevmConfig;

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

    private static object FormatAccordingToType(BigInteger value, FheValueType type) =>
        type switch
        {
            FheValueType.Bool => value == BigInteger.One,
            FheValueType.Address => AddressHelper.GetChecksumAddress($"0x{value:X40}"),
            FheValueType.Bytes64 => $"0x{value:X128}",
            FheValueType.Bytes128 => $"0x{value:X256}",
            FheValueType.Bytes256 => $"0x{value:X512}",
            FheValueType.UInt8 => (byte)value,
            FheValueType.UInt16 => (ushort)value,
            FheValueType.UInt32 => (uint)value,
            FheValueType.UInt64 => (ulong)value,
            FheValueType.UInt128 => (UInt128)value,
            FheValueType.UInt256 => value,
            _ => value
        };

    private static Dictionary<string, object> BuildUserDecryptedResults(List<string> handles, List<BigInteger> listBigIntDecryptions) =>
        handles
        .Zip(listBigIntDecryptions, (h, d) => new { h, d = d })
        .ToDictionary(o => o.h, o => FormatAccordingToType(o.d, HandleHelper.GetValueType(o.h)));

    private static Dictionary<string, object> BuildUserDecryptedResults2(List<string> handles, TypedPlaintext[] result) =>
        handles
        .Zip(result, (h, r) => new { h, r = r })
        .ToDictionary(o => o.h, o => FormatAccordingToType(new BigInteger(o.r.Bytes), (FheValueType)o.r.FheType), StringComparer.OrdinalIgnoreCase);

    // https://github.com/zama-ai/fhevm-relayer/blob/96151ef300f787658c5fbaf1b4471263160032d5/src/http/userdecrypt_http_listener.rs#L20
    private class RelayerUserDecryptPayload
    {
        public class RequestValidity
        {
            // Seconds since the Unix Epoch (1/1/1970 00:00:00).
            public required string startTimestamp { get; set; }
            public required string durationDays { get; set; }
        };

        public required HandleContractPair[] handleContractPairs { get; set; }
        public required RequestValidity requestValidity { get; set; }
        public required string contractsChainId { get; set; }
        public required string[] contractAddresses { get; set; } // With 0x prefix.
        public required string userAddress { get; set; } // With 0x prefix.
        public required string signature { get; set; } // Without 0x prefix.
        public required string publicKey { get; set; } // Without 0x prefix.
        public required string extraData { get; set; } // With 0x prefix. Default: 0x00
    }

    private class PayloadForVerification
    {
        public required string? signature { get; set; }
        public required string client_address { get; set; }
        public required string enc_key { get; set; }
        public required string[] ciphertext_handles { get; set; }
        public required string eip712_verifying_contract { get; set; }
    }

    // Map gRPC TypedPlaintext message
    private class TypedPlaintext
    {
        // The actual plaintext in bytes.
        [JsonPropertyName("bytes")]
        public required byte[] Bytes { get; set; }

        // The type of plaintext encrypted. The type should match FheType from tfhe-rs:
        // https://github.com/zama-ai/tfhe-rs/blob/main/tfhe/src/high_level_api/mod.rs
        [JsonPropertyName("fhe_type")]
        public required int FheType { get; set; }
    }

    private class UserDecryptionResponseHex
    {
        public required string payload { get; set; }
        public required string signature { get; set; }
    }

    private class AggResp
    {
        public required UserDecryptionResponseHex[] response { get; set; }
    }

    private static void CheckDeadlineValidity(DateTimeOffset startTime, int durationDays)
    {
        if (durationDays <= 0)
            throw new InvalidDataException($"Invalid durationDays value: {durationDays}");

        const int MAX_USER_DECRYPT_DURATION_DAYS = 365;
        if (durationDays > MAX_USER_DECRYPT_DURATION_DAYS)
            throw new InvalidDataException($"Invalid durationDays value: {durationDays} (max value is {MAX_USER_DECRYPT_DURATION_DAYS})");

        var now = DateTimeOffset.Now;

        if (startTime > now)
            throw new InvalidDataException($"Invalid startTime: {startTime} (set in the future)");

        if (startTime.AddDays(durationDays) < now)
            throw new InvalidDataException("User decrypt request has expired");
    }

    public async Task<Dictionary<string, object>> Decrypt(
        HandleContractPair[] _handles,
        string privateKey,
        string publicKey,
        string? signature,
        string[] contractAddresses,
        string userAddress,
        DateTimeOffset startTime,
        int durationDays)
    {
        using var pubKey = PublicEncKeyMlKem512.Deserialize(Convert.FromHexString(Helpers.Remove0xIfAny(publicKey)));
        using var privKey = PrivateEncKeyMlKem512.Deserialize(Convert.FromHexString(Helpers.Remove0xIfAny(privateKey)));

        // Casting handles if string
        string? signatureSanitized = signature != null ? Helpers.Remove0xIfAny(signature) : null;
        string publicKeySanitized = Helpers.Remove0xIfAny(publicKey);

        HandleContractPair[] handles =
            _handles
            .Select(hc =>
                new HandleContractPair
                {
                    Handle = Helpers.Ensure0xPrefix(hc.Handle),
                    ContractAddress = AddressHelper.GetChecksumAddress(hc.ContractAddress),
                }
            ).ToArray();

        CheckEncryptedBits(handles.Select(h => h.Handle));
        CheckDeadlineValidity(startTime, durationDays);

        if (contractAddresses.Length == 0)
            throw new InvalidOperationException("contractAddresses is empty");

        const int MAX_USER_DECRYPT_CONTRACT_ADDRESSES = 10;
        if (contractAddresses.Length > MAX_USER_DECRYPT_CONTRACT_ADDRESSES)
            throw new InvalidOperationException($"contractAddresses length exceeds {MAX_USER_DECRYPT_CONTRACT_ADDRESSES}");

        /* TODO

        const acl = new ethers.Contract(_fhevmConfig.AclContractAddress, aclABI, provider);
        const verifications = handles.map(async({ handle, contractAddress }) => {
            const userAllowed = await acl.persistAllowed(handle, userAddress);
            const contractAllowed = await acl.persistAllowed(handle, contractAddress);
            if (!userAllowed)
                throw new Error(`User ${ userAddress } is not authorized to user decrypt handle ${handle}!`);
            if (!contractAllowed)
                throw new Error(`dapp contract ${ contractAddress } is not authorized to user decrypt handle ${handle}!`);
            if (userAddress === contractAddress)
                throw new Error(`userAddress ${ userAddress } should not be equal to contractAddress when requesting user decryption!`);
        });

        await Promise.all(verifications).catch((e) =>
        {
            throw e;
        });
        */

        const string DefaultExtraData = "0x00";

        var payload = new RelayerUserDecryptPayload
        {
            handleContractPairs = handles,
            requestValidity = new RelayerUserDecryptPayload.RequestValidity
            {
                startTimestamp = Helpers.DataTimeToTimestamp(startTime).ToString(CultureInfo.InvariantCulture),
                durationDays = durationDays.ToString(CultureInfo.InvariantCulture),
            },
            contractsChainId = _fhevmConfig.ChainId.ToString(CultureInfo.InvariantCulture),
            contractAddresses = contractAddresses.Select(c => AddressHelper.GetChecksumAddress(c)).ToArray(),
            userAddress = AddressHelper.GetChecksumAddress(userAddress),
            signature = signatureSanitized ?? "",
            publicKey = publicKeySanitized,
            extraData = DefaultExtraData,
        };

        using HttpClient httpClient = new();

        string pubKeyUrl =  $"{_fhevmConfig.RelayerUrl}/v1/user-decrypt";
        string payload_json = JsonSerializer.Serialize(payload);

        using StringContent content = new(payload_json, Encoding.UTF8, "application/json");
        using HttpResponseMessage response = await httpClient.PostAsync(pubKeyUrl, content);
        response.EnsureSuccessStatusCode(); // throw if not 2xx

        string agg_resp_json = await response.Content.ReadAsStringAsync();

        var agg_resp = JsonSerializer.Deserialize<AggResp>(agg_resp_json) ?? throw new InvalidDataException("Invalid agg_resp");
        agg_resp_json = JsonSerializer.Serialize(agg_resp.response);

        var payloadForVerification = new PayloadForVerification
        {
            signature = signatureSanitized,
            client_address = userAddress,
            enc_key = publicKeySanitized,
            ciphertext_handles = handles.Select(h => Helpers.Remove0xIfAny(h.Handle)).ToArray(),
            eip712_verifying_contract = _fhevmConfig.VerifyingContractAddress,
        };

        string payloadForVerification_json = JsonSerializer.Serialize(payloadForVerification, _json_serialization_options);

        using var client = Client.Create(_indexedKmsSigners, userAddress, fheParameter: "default");

        string resultJson;
        nint c_result_json = IntPtr.Zero;
        try
        {
            int error = SafeNativeMethods.TKMS_process_user_decryption_resp_from_cs(
                client.Handle,
                payloadForVerification_json,
                _eip712Domain_json,
                agg_resp_json,
                pubKey.Handle,
                privKey.Handle,
                verify: true,
                out c_result_json);

            if (error != 0)
                throw new KmsException(error);

            resultJson =
                Marshal.PtrToStringUTF8(c_result_json)
                ?? throw new InvalidDataException("Invalid utf-8 response from KMS");
        }
        finally
        {
            SafeNativeMethods.TKMS_free_CString(c_result_json);
        }

        TypedPlaintext[] result =
            JsonSerializer.Deserialize<TypedPlaintext[]>(resultJson, _json_serialization_options)
            ?? throw new InvalidDataException("Invalid json response from KMS");

        //List<BigInteger> listBigIntDecryptions = result.Select(tp => new BigInteger(tp.Bytes)).ToList();
        //return BuildUserDecryptedResults(handles.Select(h => h.Handle).ToList(), listBigIntDecryptions);

        // Prefer building result based on the fhe_type returned by the server.
        return BuildUserDecryptedResults2(handles.Select(h => h.Handle).ToList(), result);
    }
}
