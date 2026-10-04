import json; r=json.load(open("/tmp/hm-review-probes/agent_probe.out.json"))
for k,v in r.items(): print(f"{k:30s} rc={v['rc']} {v['code']} {v['ms']}ms rss={v['maxrss_kib']}KiB req={v['request_hex']} srv={v['server']}")
print(json.dumps(r["control_and_invalid_comment"]["data"], ensure_ascii=True)); print(r["empty_keytype"]["data"])
