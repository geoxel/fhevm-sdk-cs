namespace RelayerSDK.Tools;

public abstract class DisposableOnce : IDisposable
{
    private volatile bool _alrreadyDisposed;

    public void Dispose()
    {
        if (!_alrreadyDisposed)
        {
            DisposeManagedResources();
            _alrreadyDisposed = true;
        }
        GC.SuppressFinalize(this);
    }

    protected abstract void DisposeManagedResources();
}
