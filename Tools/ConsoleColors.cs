namespace FhevmSDK.Tools;

public static class ConsoleColors
{
    public static readonly string ANSI_RESET = "\u001B[0m";
    public static readonly string ANSI_BLACK = "\u001B[30m";
    public static readonly string ANSI_RED = "\u001B[31m";
    public static readonly string ANSI_GREEN = "\u001B[32m";
    public static readonly string ANSI_YELLOW = "\u001B[33m";
    public static readonly string ANSI_BLUE = "\u001B[34m";
    public static readonly string ANSI_PURPLE = "\u001B[35m";
    public static readonly string ANSI_CYAN = "\u001B[36m";
    public static readonly string ANSI_WHITE = "\u001B[37m";

    private static readonly string[] ANSI_COLORS = [
            ANSI_RESET,
            ANSI_BLACK,
            ANSI_RED,
            ANSI_GREEN,
            ANSI_YELLOW,
            ANSI_BLUE,
            ANSI_PURPLE,
            ANSI_CYAN,
            ANSI_WHITE,
    ];

    public static readonly string RESET = "(CC-RESET)";
    public static readonly string BLACK = "(CC-BLACK)";
    public static readonly string RED = "(CC-RED)";
    public static readonly string GREEN = "(CC-GREEN)";
    public static readonly string YELLOW = "(CC-YELLOW)";
    public static readonly string BLUE = "(CC-BLUE)";
    public static readonly string PURPLE = "(CC-PURPLE)";
    public static readonly string CYAN = "(CC-CYAN)";
    public static readonly string WHITE = "(CC-WHITE)";

    private static readonly string[] CODES = [
            RESET,
            BLACK,
            RED,
            GREEN,
            YELLOW,
            BLUE,
            PURPLE,
            CYAN,
            WHITE,
    ];

    public static string Colorize(string text)
    {
        for (int i = 0; i < ANSI_COLORS.Length; i++)
        {
            text = text.Replace(CODES[i], ANSI_COLORS[i]);
        }
        return text;
    }

    public static void WriteLine(string text)
    {
        Console.WriteLine(Colorize(text));
    }
}
