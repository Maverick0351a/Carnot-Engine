# JFR crypto profile
Start:
```
java -XX:StartFlightRecording=filename=aegisq_recording.jfr,settings=aegisq_crypto.jfc -jar MyApp.jar
```
Inspect/convert:
```
jfr print --events jdk.tls.TlsHandshake aegisq_recording.jfr > jfr_tls.txt
python3 tools/ingest/jfr_to_bom.py jfr_tls.txt jfr.bom.json
```
