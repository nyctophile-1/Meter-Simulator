using MeterSimulator.DLMS;

Console.WriteLine("Starting DLMS Meter Simulator...");

// ---- Create ONE meter ----
var meter = new DLMSMeter(
    meterNo: "MTR001",
    logicalName: "0.0.42.0.0.255",
    clientAddress: 30,
    serverAddress: 1
);

// ---- Set one OBIS value ----
meter.SetValue("1.0.1.8.0.255", 12345.67m);

// ---- Start DLMS server on TCP port 4059 ----
var server = new DLMSServerHost(meter, port: 4059);
server.Start();

Console.WriteLine("Meter running. Press ENTER to stop...");
Console.ReadLine();

// ---- Stop server ----
server.Stop();

Console.WriteLine("Meter stopped.");
