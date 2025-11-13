namespace FhevmSDK.Tools;

public static class EnumerableExtensions
{
    public static void ForEach<T>(this IEnumerable<T> elements, Action<T> action)
    {
        foreach (T e in elements)
            action(e);
    }

    public static void ForEach<T>(this IEnumerable<T> elements, Action<int, T> action)
    {
        int index = 0;
        foreach (T e in elements)
        {
            action(index, e);
            ++index;
        }
    }
}
