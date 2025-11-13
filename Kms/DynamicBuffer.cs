namespace RelayerSDK.Kms;

public sealed class DynamicBuffer : IDisposable
{
    private SafeNativeMethods.DynamicBuffer _buffer;

    internal DynamicBuffer(SafeNativeMethods.DynamicBuffer buffer)
    {
        _buffer = buffer;
    }

    ~DynamicBuffer()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        SafeNativeMethods.DynamicBuffer_Destroy(ref _buffer);
    }

    public byte[] ToArray() =>
        SafeNativeMethods.DynamicBuffer_ToArray(_buffer);
}
