# ArubaCX Support in netbox-orb

This is a bit hacky approach of supporting **ArubaCX** latest devices, but for sure it works perfectly. All you need is to spin latest **docker.io/netboxlabs/orb-agent:develop** docker image and replace 
files in
**/usr/local/lib/python3.12/site-packages/napalm** with this repository files. There are no prebuild docker image yet, so you have to do it yourself. Then in agent.yml config use "driver: aoscx_v2".

```
mv device_discovery/discovery.py /usr/local/lib/python3.12/site-packages/device_discovery/discovery.py
mv aoscx_v2/ /usr/local/lib/python3.12/site-packages/napalm/
mv _SUPPORTED_DRIVERS.py /usr/local/lib/python3.12/site-packages/napalm/
mv __init__.py /usr/local/lib/python3.12/site-packages/napalm/
```

test_drive.py is the script for testing inside the container

## Docker

You can automate it by starting the docker container of netbox-orb with the parameters (docker-compose):
```
services:
  netbox-orb:
    #image: netboxlabs/orb-agent:latest
    image: docker.io/netboxlabs/orb-agent:develop
    restart: on-failure
    container_name: netbox-orb
    network_mode: host
    volumes:
      - /srv/dockers/netbox-orb:/opt/orb/
    entrypoint: ["/bin/bash","-c"]
    command: ["apt update && apt-get install -yy procps nano && pip3 install -r /opt/orb/drivers.txt && cp /opt/orb/device_discovery/discovery.py 
/usr/local/lib/python3.12/site-packages/device_discovery/ && cp /opt/orb/__init__.py /usr/local/lib/python3.12/site-packages/napalm/ && cp /opt/orb/_SUPPORTED_DRIVERS.py 
/usr/local/lib/python3.12/site-packages/napalm/_SUPPORTED_DRIVERS.py && cp -r /opt/orb/aoscx_v2/ /usr/local/lib/python3.12/site-packages/napalm/ && cp /opt/orb/s350.py 
/usr/local/lib/python3.12/site-packages/napalm_s350/s350.py && /usr/local/bin/orb-agent run -c /opt/orb/agent.yaml"]
    environment:
      DIODE_CLIENT_ID: XXX
      DIODE_CLIENT_SECRET: XXX
      INSTALL_DRIVERS_PATH: /opt/orb/drivers.txt
      LOG_LEVEL: DEBUG
```

BTW put these files in /srv/dockers/netbox-orb

# Test

```
python3 - <<'PY'
from napalm import get_network_driver
D = get_network_driver("aoscx_v2")
d = D("192.168.1.20","admin","admin", optional_args={"api_version":"auto","verify":False})
d.open()
print("facts ok:", d.get_facts()["uptime"] >= 0)
print("vlans types:", [(k, type(k).__name__) for k in list(d.get_vlans().keys())[:10]])
ifs = d.get_interfaces()
print("iface numeric:", all(isinstance(v["speed"], float) for v in ifs.values()))
print("counters ints:", all(isinstance(x,int) for v in d.get_interfaces_counters().values() for x in v.values()))
d.close()
PY
```
