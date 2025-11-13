namespace RelayerSDK.Kms;

public sealed class KmsException : Exception
{
    public int Error { get; }

    public KmsException()
    {
    }

    public KmsException(int error)
    {
        Error = error;
    }
}
