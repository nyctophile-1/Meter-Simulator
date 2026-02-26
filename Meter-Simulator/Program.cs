using MeterSimulator.Config;
using MeterSimulator.Simulation;

var config = new MeterConfig
{
    MeterCount = 100,
    BasePort = 4059
};

var manager = new MeterManager(config);

manager.Initialize();
manager.StartAll();

Console.WriteLine("Press ENTER to stop...");
Console.ReadLine();

manager.StopAll();