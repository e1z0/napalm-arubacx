import argparse, json
from napalm_aoscx_v2.driver import AOSCXDriver

p = argparse.ArgumentParser()
p.add_argument("--host", required=True)
p.add_argument("--user", required=True)
p.add_argument("--password", required=True)
p.add_argument("--api", default="10.13")
p.add_argument("--verify", action="store_true", help="verify TLS cert")
args = p.parse_args()

optional = {"api_version": args.api, "verify": args.verify}
d = AOSCXDriver(args.host, args.user, args.password, optional_args=optional)

d.open()
try:
    print("is_alive:", d.is_alive())
    facts = d.get_facts()
    print("facts:", json.dumps(facts, indent=2))
    cfg = d.get_config(retrieve="all")
    open("running.json","w").write(cfg["running"])
    open("startup.json","w").write(cfg["startup"])
    print("Saved running.json and startup.json")
finally:
    d.close()
