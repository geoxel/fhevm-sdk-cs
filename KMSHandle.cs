using System;
using System.Runtime.InteropServices;

namespace RelayerSDK;

public abstract class KMSHandle : IDisposable
{
    private nint _handle;

    public nint Handle => _handle;

    protected KMSHandle(nint handle)
    {
        _handle = handle;
    }

    public abstract void Dispose();

    protected nint GetHandleAndFlush() =>
        Interlocked.CompareExchange(ref _handle, value: IntPtr.Zero, comparand: _handle);
}
