using Fhe;
using Nethereum.Util;
using System.Globalization;
using System.Text;

namespace FhevmSDK.Tools;

public static class HandleHelper
{
    public static FheValueType GetValueType(string handle) =>
        (FheValueType)int.Parse(handle[^4..^2], NumberStyles.HexNumber);

    public static bool IsValid(string handle)
    {
        handle = Helpers.Remove0xIfAny(handle);
        if (handle.Length != 64)
            return false;

        FheValueType type = GetValueType(handle);
        if (!Enum.IsDefined(typeof(FheValueType), type))
            return false;

        return true;
    }

    private static readonly byte[] RAW_CT_HASH_DOMAIN_SEPARATOR = Encoding.UTF8.GetBytes(""); // "ZK-w_rct" ????? V8 / V9 ?
    private static readonly byte[] HANDLE_HASH_DOMAIN_SEPARATOR = Encoding.UTF8.GetBytes(""); // "ZK-w_hdl" ?????

    // So bad, KeccakDigest is internal...
    // private static byte[] KeccakDigest256(params byte[] arrays)
    // {
    //     KeccakDigest keccakDigest = new(bitLength: 256);
    //     arrays.ForEach(array => keccakDigest.BlockUpdate(array, 0, array.Length));
    //     var digest = new byte[digest.GetDigestSize()];
    //     keccakDigest.DoFinal(digest, 0);
    //     return digest;
    // }

    private static byte[] KeccakDigest256(params byte[][] arrays) =>
        // Oh no... Nethereum authors misspelled Keccak!
        Sha3Keccack.Current.CalculateHash(arrays.SelectMany(a => a).ToArray());

    // Should be identical to:
    // https://github.com/zama-ai/fhevm-backend/blob/bae00d1b0feafb63286e94acdc58dc88d9c481bf/fhevm-engine/zkproof-worker/src/verifier.rs#L301
    public static string[] CreateHandles(
        IReadOnlyList<FheValueType> fheValueTypes,
        byte[] ciphertextWithZKProof,
        string aclContractAddress,
        ulong chainId,
        byte ciphertextVersion)
    {
        byte[] blobHash = KeccakDigest256(RAW_CT_HASH_DOMAIN_SEPARATOR, ciphertextWithZKProof);
        byte[] aclContractAddress20Bytes = Convert.FromHexString(Helpers.Remove0xIfAny(aclContractAddress));
        byte[] chainId32Bytes = Convert.FromHexString($"{chainId:X64}");

        return
            Enumerable.Range(0, fheValueTypes.Count)
            .Zip(fheValueTypes, (index, fheValueType) =>
            {
                byte[] handleHash = KeccakDigest256(
                    HANDLE_HASH_DOMAIN_SEPARATOR,
                    blobHash,
                    [(byte)index],
                    aclContractAddress20Bytes,
                    chainId32Bytes);

                byte[] handleData = [.. handleHash[0..21], (byte)index, .. chainId32Bytes[24..32], (byte)fheValueType, ciphertextVersion];

                return Helpers.To0xHexString(handleData);
            })
            .ToArray();
    }
}
