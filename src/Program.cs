using V3_Linode;
using V3_WebServer;
using V3_Shared;
using V3_Firewall;
namespace V3_FUC;

class V3_FucMain
{

    public static void ClearCurrentConsoleLine()
    {
        int currentLineCursor = Console.CursorTop;
        Console.SetCursorPosition(0, Console.CursorTop);
        Console.Write(new string(' ', Console.WindowWidth));
        Console.SetCursorPosition(0, currentLineCursor);
    }

    public static long getTimestamp()
    {
        return DateTimeOffset.Now.ToUnixTimeSeconds();
    }

    public static async Task Main(string[] args)
    {

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("PurpleMaze's Firewall Unique Conveoyr (FUC)");
        Console.WriteLine("CC 2023-2024 @m2p_ (MathiAs2Pique_)");
        Console.ForegroundColor = ConsoleColor.White;
        // Initialization
        Console.WriteLine("# Initialisation");
        Console.WriteLine("# Instanciating classes");

        V3_SharedClass v3shared = new();
        V3_LinodeClass linApi = new(v3shared);
        V3_FirewallMasterClass fwmc = new(v3shared, linApi);
        V3_WebServerClass webServer = new(linApi, v3shared, fwmc);

        
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("# Setting variables up");
        Console.ForegroundColor = ConsoleColor.White;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("# Fetching firewalls");
        linApi.InitFirewalls();
        Console.WriteLine("# Setup ok");
        Console.ForegroundColor = ConsoleColor.White;

        int port = 6001;
        if(args.Length > 0)
        {
            port = int.Parse(args[0]);
        }

        // Infinite loop
        while (true)
        {
            await webServer.startWebServer(port, v3shared, linApi);
            Console.WriteLine("main loop/ web server stopped");
        }
    }
}