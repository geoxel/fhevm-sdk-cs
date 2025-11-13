namespace FhevmSDK.Tools;

public class DisposableList : DisposableOnce
{
    private readonly List<IDisposable> _list = new List<IDisposable>();

    public DisposableList()
    {
    }

    public DisposableList(IEnumerable<IDisposable> disposables)
    {
        _list = disposables.ToList();
    }

    protected override void DisposeManagedResources()
    {
        _list
            .AsEnumerable()
            .Reverse()
            .ForEach(d => d?.Dispose());
    }
}
