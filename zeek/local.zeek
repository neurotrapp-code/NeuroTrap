# NeuroTrap/CADN Zeek site policy — JSON logging for the pipeline.
@load policy/tuning/json-logs.zeek
# Explicit fallback if the policy above is unavailable:
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Day 13: ensure the connection + protocol analyzers the pipeline ingests are
# loaded (conn/http/ssh/dns are produced by these). They are on by default, but
# we load explicitly so the deliverable holds on a stripped-down Zeek build.
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/dns
