using Microsoft.Diagnostics.Tracing; using Microsoft.Diagnostics.Tracing.Session; using System; using System.Text.Json;
class Program {
  static readonly Guid Schannel = new Guid("1f678132-5938-4686-9f55-c8df9f226e64");
  static void Main() {
    if (!(TraceEventSession.IsElevated() ?? false)) { Console.Error.WriteLine("Admin required"); return; }
    using var s = new TraceEventSession("CarnotSChannel");
    Console.CancelKeyPress += (o,e)=> s.Stop();
    s.EnableProvider(Schannel, TraceEventLevel.Informational);
    s.Source.Dynamic.All += (ev)=> {
      if (ev.ProviderGuid != Schannel) return;
      var obj = new {
        source="runtime.etw", source_type="ETW_SChannel",
        pid=ev.ProcessID, event_id=ev.ID, event_name=ev.EventName,
        protocol = ev.PayloadNames.Length>0 ? ev.PayloadByName("Protocol")?.ToString() : null,
        ciphersuite = ev.PayloadNames.Length>0 ? ev.PayloadByName("CipherSuite")?.ToString() : null,
        target_host = ev.PayloadNames.Length>0 ? ev.PayloadByName("TargetName")?.ToString() : null,
        timestamp = ev.TimeStamp.ToUniversalTime().ToString("o")
      };
      Console.WriteLine(JsonSerializer.Serialize(obj));
    };
    Console.WriteLine("Carnot ETW SChannel monitor running... Ctrl+C to stop.");
    s.Source.Process();
  }
}
