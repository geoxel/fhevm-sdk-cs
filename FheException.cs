using System;

namespace RelayerSDK;

public sealed class FheException : Exception
{
    public int Error { get; private set; }

    public FheException()
    {
    }

    public FheException(int error)
    {
        Error = error;
    }
}
