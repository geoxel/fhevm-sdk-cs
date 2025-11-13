namespace FhevmSDK.Tools;

public static class Helpers
{
    public static string Remove0xIfAny(string value) =>
        value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;

    public static string Ensure0xPrefix(string value) =>
        value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value : "0x" + value;

    public static string To0xHexString(byte[] value) =>
        "0x" + Convert.ToHexString(value).ToLower();

    public static long DataTimeToTimestamp(DateTimeOffset value) =>
        value.ToUnixTimeSeconds();

    public static bool IsThresholdReached(
        string[] recoveredAddresses,
        string[] coprocessorSigners,
        int _thresholdSigners)
    {
        string? duplicatedAddress =
            recoveredAddresses
            .GroupBy(a => a)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .FirstOrDefault();

        if (duplicatedAddress != null)
            throw new InvalidDataException($"Duplicate KMS signer address found: {duplicatedAddress} appears multiple times in recovered addresses");

        string? unknownRecoveredAddress = recoveredAddresses.FirstOrDefault(ra => !coprocessorSigners.Contains(ra));
        if (unknownRecoveredAddress != null)
            throw new InvalidDataException($"Invalid address found: {unknownRecoveredAddress} is not in the list of KMS signers");

        return recoveredAddresses.Length >= _thresholdSigners;
    }
}
