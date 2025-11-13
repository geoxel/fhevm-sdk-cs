using Fhe;

namespace FhevmSDK.Tools;

public static class FheValueHelper
{
    public static IReadOnlyDictionary<FheValueType, int> EValueBitCount { get; } = new Dictionary<FheValueType, int>
    {
        { FheValueType.Bool, 2 },
        { FheValueType.UInt8, 8 },
        { FheValueType.UInt16, 16 },
        { FheValueType.UInt32, 32 },
        { FheValueType.UInt64, 64 },
        { FheValueType.UInt128, 128 },
        { FheValueType.UInt256, 256 },
        { FheValueType.Address, 160 },
        { FheValueType.Bytes64, 512 },
        { FheValueType.Bytes128, 1024 },
        { FheValueType.Bytes256, 2048 },
    };

    public static int GetBitCount(FheValueType valueType) =>
        EValueBitCount[valueType];
}
