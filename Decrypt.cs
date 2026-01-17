using Fhe;
using FhevmSDK.Kms;
using FhevmSDK.Tools;

namespace FhevmSDK;

public abstract class Decrypt : DisposableOnce
{
    protected class Eip712DomainMsg
    {
        public required string name { get; set; }
        public required string version { get; set; }
        public required byte[] chain_id { get; set; }
        public required string verifying_contract { get; set; }
        public byte[]? salt { get; set; }
    }

    protected static void CheckEncryptedBits(IEnumerable<string> handles)
    {
        int totalBits = 0;

        foreach (string h in handles)
        {
            string handle = Helpers.Remove0xIfAny(h);

            if (handle.Length != 64)
                throw new InvalidDataException($"Invalid handle length: {handle}");

            FheValueType typeDiscriminant = HandleHelper.GetValueType(handle);

            if (!FheValueHelper.EValueBitCount.TryGetValue(typeDiscriminant, out int size))
                throw new InvalidDataException($"Invalid handle type: {handle}");

            totalBits += size;

            // enforce 2048‑bit limit
            if (totalBits > 2048)
                throw new InvalidDataException("Cannot decrypt more than 2048 encrypted bits in a single request");
        }
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

    protected static Dictionary<string, object> BuildDecryptedResults(
        IReadOnlyList<string> handles,
        IReadOnlyList<FheValueType> types,
        IReadOnlyList<BigInteger> values)
    {
        if (handles.Count != types.Count || handles.Count != values.Count)
            throw new InvalidDataException($"Invalid counts in results decrypting. Handles: {handles.Count}, Types: {types.Count}, Bytes: {values.Count}");

        return
            Enumerable.Range(0, handles.Count)
            .Select(i => new
            {
                h = handles[i],
                v = FormatAccordingToType(values[i], types[i]),
            })
            .ToDictionary(o => o.h, o => o.v, StringComparer.OrdinalIgnoreCase);
    }
}
