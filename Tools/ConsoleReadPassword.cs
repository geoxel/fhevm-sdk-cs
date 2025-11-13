using System.Text;

namespace FhevmSDK.Tools;

public static class ConsoleReadPassword
{
    public static string Read()
    {
        StringBuilder sb = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo cki = Console.ReadKey(true);
            if (cki.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }

            if (cki.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    Console.Write("\b \b");
                    sb.Length--;
                }

                continue;
            }

            Console.Write('*');
            sb.Append(cki.KeyChar);
        }

        return sb.ToString();
    }
}
