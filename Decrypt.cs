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
}
