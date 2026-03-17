using MeterSimulator.Config;
using MeterSimulator.Simulation;
using Microsoft.Extensions.Configuration;

public class Program
{
    public static void Main(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        var config = configuration.GetSection("MeterConfig").Get<MeterConfig>();

        var manager = new MeterManager(config);

        manager.Initialize();
        manager.StartAll();

        Console.WriteLine("Press ENTER to stop...");
        Console.ReadLine();

        manager.StopAll();
    }
}