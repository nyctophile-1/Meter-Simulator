using MeterSimulator.Config;
using MeterSimulator.Simulation;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;


//public static void Main(string[] args)
//{ 
//    // app. start (args) or --shared file---
//    //args[0] = Json{ with ur required props }
//    // how to return values  {once done}
//    // how to share errors 
//    // -- get a liost of copmmands to run 
//    // -- billing [size of payload]
//    // -- frequency
//}

var config = new MeterConfig
{
    MeterCount = 500,
    BasePort = 4059
};

var manager = new MeterManager(config);

manager.Initialize();
manager.StartAll();

Console.WriteLine("Press ENTER to stop...");
Console.ReadLine();

manager.StopAll();