# SChannel ETW consumer
Build:
```
cd integrations/windows/SChannelETW
dotnet restore
dotnet add package Microsoft.Diagnostics.Tracing.TraceEvent
dotnet build -c Release
```
Run as Administrator:
```
bin/Release/net8.0/SChannelETW.exe > runtime.etw.jsonl
```
