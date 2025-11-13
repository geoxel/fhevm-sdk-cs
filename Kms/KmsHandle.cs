namespace RelayerSDK.Kms;

public abstract class KmsHandle : IDisposable
{
    private nint _handle;

    public nint Handle => _handle;

    protected KmsHandle(nint handle)
    {
        _handle = handle;
    }

    ~KmsHandle()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        nint handle = Interlocked.CompareExchange(ref _handle, value: IntPtr.Zero, comparand: _handle);
        if (handle != IntPtr.Zero)
            DestroyHandle(handle);
    }

    protected abstract void DestroyHandle(nint handle);

    protected static void CheckError(int error)
    {
        if (error != 0)
            throw new KmsException(error);
    }

    internal delegate int Oper1Func<in T1>(T1 arg1, out nint result);
    internal delegate int Oper2Func<in T1, in T2>(T1 arg1, T2 arg2, out nint result);

    internal static nint Oper1n<A>(Oper1Func<A> func, A a)
    {
        int error = func(a, out nint out_value);
        if (error != 0)
            throw new KmsException(error);
        return out_value;
    }
}
