import json
import re
import urllib.parse
import urllib3
import requests

from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException
from pyaoscx.session import Session
from pyaoscx.exceptions.parameter_error import ParameterError

import os, pathlib, json

def _to_int(v, default=0):
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return int(v)
        return int(float(v))
    except Exception:
        return default


def _truthy(x):
    if isinstance(x, bool):
        return x
    if isinstance(x, str):
        return x.lower() in ("up", "on", "enabled", "true", "yes", "1")
    if isinstance(x, (int, float)):
        return x != 0
    return False


class AOSCXDriver(NetworkDriver):
    """
    NAPALM shim for Aruba AOS-CX (REST v10.xx) using pyaoscx v2.

    Implemented (read-only):
      - open, close, is_alive
      - get_config
      - get_facts
      - get_interfaces
      - get_interfaces_ip
      - get_interfaces_counters
      - get_lldp_neighbors
      - get_vlans
      - get_arp_table (safe empty)
      - get_mac_address_table (safe empty)

    All numeric fields are sanitized to integers/floats (never None) to avoid
    client code doing comparisons like `> 0` crashing with NoneType.
    """

    def _trace(self, name, payload):
        d = "/opt/orb/out"
        if not d: return
        try:
            pathlib.Path(d).mkdir(parents=True, exist_ok=True)
            p = os.path.join(d, f"{self.hostname}_{name}.json")
            with open(p, "w") as f: json.dump(payload, f, indent=2)
        except Exception:
            pass

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.api_version = "10.09"
        #self.optional_args = {"api_version":"auto","verify":False,"skip_vlans":True,"skip_counters":True,"skip_lldp":True}
        self.optional_args = optional_args or {}

        # defaults (only if caller didn't supply)
        self.optional_args.setdefault("api_version", "10.09")
        self.optional_args.setdefault("verify", False)
        self.optional_args.setdefault("skip_vlans", False)
        self.optional_args.setdefault("skip_counters", False)
        self.optional_args.setdefault("skip_lldp", False)


        # "auto"/"latest" or explicit "10.13"
        self.requested_api = str(self.optional_args.get("api_version", "auto"))

        # TLS verify: False | True | "/path/to/ca.pem"
        self.verify = self.optional_args.get("verify", False)
        if self.verify is False:
            urllib3.disable_warnings()

        self.session = None          # pyaoscx Session
        self.http = None             # requests.Session (cookie carried by pyaoscx)
        self.api_version = None
        self.base = None             # https://<host>/rest/v10.xx

    # --------------------------- helpers ---------------------------------

    def _probe_latest_from_switch(self):
        try:
            r = requests.get(f"https://{self.hostname}/rest",
                             verify=self.verify, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
            latest = data.get("latest", {}).get("version", "")
            if latest.startswith("v"):
                latest = latest[1:]
            return latest or None
        except Exception:
            return None

    def _pick_api_version(self):
        candidates = []
        req = self.requested_api.lower()
        if req in ("auto", "latest"):
            sw_latest = self._probe_latest_from_switch()
            if sw_latest:
                candidates.append(sw_latest)
        else:
            candidates.append(self.requested_api)

        for v in ["10.13", "10.12", "10.11", "10.10", "10.09", "10.08", "10.04"]:
            if v not in candidates:
                candidates.append(v)
        return candidates

    def _get_json(self, url, params=None, default=None, ok_only=False):
        resp = self.http.get(url, params=params, verify=self.verify, timeout=self.timeout)
        if ok_only:
            resp.raise_for_status()
        if not resp.ok or not resp.text:
            return default
        try:
            return resp.json()
        except ValueError:
            return default

    # ------------------------ session lifecycle --------------------------

    def open(self):
        last_err = None
        for ver in self._pick_api_version():
            try:
                s = Session(self.hostname, ver)  # pyaoscx v2: no verify arg here
                s.open(self.username, self.password)
                self.session = s
                self.http = s.s  # underlying requests.Session
                self.api_version = ver
                self.base = f"https://{self.hostname}/rest/v{self.api_version}"
                return
            except ParameterError as e:
                last_err = e
                continue
            except Exception as e:
                last_err = e
                continue
        raise ConnectionException(
            f"Unable to open session; tried API versions {self._pick_api_version()}. Last error: {last_err}"
        )

    def close(self):
        # Quiet, tolerant logout: treat 401/403 as "already expired"
        try:
            if self.http and self.base:
                try:
                    r = self.http.post(f"{self.base}/logout", verify=self.verify, timeout=5)
                    _ = r.status_code in (200, 204, 401, 403)
                except Exception:
                    pass
            try:
                if self.http:
                    self.http.close()
            except Exception:
                pass
        finally:
            self.http = None
            self.session = None

    def is_alive(self):
        return {"is_alive": self.http is not None}


    # ----------------------------- config --------------------------------

    def get_config(self, retrieve="all", full=False, sanitized=False):
        cfg = {"running": "", "startup": "", "candidate": ""}
        if retrieve in ("all", "running"):
            data = self._get_json(f"{self.base}/fullconfigs/running-config", ok_only=True, default={})
            cfg["running"] = json.dumps(data or {}, indent=2)
        if retrieve in ("all", "startup"):
            data = self._get_json(f"{self.base}/fullconfigs/startup-config", ok_only=True, default={})
            cfg["startup"] = json.dumps(data or {}, indent=2)
        #self._trace("get_config",cfg)
        return cfg

    # ------------------------------ facts --------------------------------

    def get_facts(self):
        """
        Return NAPALM facts with strong fallbacks for hostname, model, serial, uptime.
        """
        from datetime import datetime

        facts = {
            "vendor": "Aruba",
            "model": None,
            "hostname": None,
            "os_version": None,
            "serial_number": "",
            "uptime": 0,
            "interface_list": [],
        }
        # ---- Management / Primary IP as OBJECT (interface + CIDR) ----
        try:
            ifip = self._interfaces_ip_bulk()  # uses get_interfaces_ip()
            mg_if, mg_ip, mg_plen, fam = self._pick_management_endpoint_with_prefix(ifip)
            if mg_if:
                facts["management_interface"] = mg_if
            if mg_ip:
                cidr = f"{mg_ip}/{mg_plen or (0 if fam=='ipv4' else 64)}"
                facts["management_ip"] = mg_ip

                # string aliases (some consumers read these)
                facts["primary_ip"] = cidr
                if fam == "ipv4":
                    facts["primary_ip4"] = cidr
                else:
                    facts["primary_ip6"] = cidr
        except Exception:
            pass

        # ---- helpers ----
        def _merge_views(obj):
            if not isinstance(obj, dict):
                return obj or {}
            cfg = obj.get("configuration") if isinstance(obj.get("configuration"), dict) else {}
            st  = obj.get("status")        if isinstance(obj.get("status"), dict)        else {}
            pr  = obj.get("properties")    if isinstance(obj.get("properties"), dict)    else {}
            merged = {}
            merged.update(cfg)
            for k, v in st.items():
                merged.setdefault(k, v)
            for k, v in pr.items():
                merged.setdefault(k, v)
            for k, v in obj.items():
                if k not in ("configuration", "status", "properties"):
                    merged.setdefault(k, v)
            return merged

        def _rfind(d, keys):
            if isinstance(d, dict):
                for k in keys:
                    if k in d and d[k] not in (None, "", {}):
                        return d[k]
                for v in d.values():
                    f = _rfind(v, keys)
                    if f not in (None, "", {}):
                        return f
            elif isinstance(d, list):
                for v in d:
                    f = _rfind(v, keys)
                    if f not in (None, "", {}):
                        return f
            return None

        def _to_epoch(v):
            if v is None:
                return None
            if isinstance(v, (int, float)):
                return int(v)
            s = str(v).strip()
            try:
                return int(float(s))
            except Exception:
                pass
            try:
                # accept "...Z" as UTC
                if s.endswith("Z"):
                    s = s[:-1] + "+00:00"
                return int(datetime.fromisoformat(s).timestamp())
            except Exception:
                return None

        def _scan_all_subsystems(model_first=False):
            """Scan /system/subsystems/* objects; return (serial, model) if found."""
            serial_out, model_out = None, None
            subs = self._get_json(f"{self.base}/system/subsystems", default={}) or {}
            if not isinstance(subs, dict):
                return None, None
            for _, ref in subs.items():
                try:
                    obj = self._get_json(f"https://{self.hostname}{ref}", default={}) or {}
                    # serial candidates
                    sn = (
                        obj.get("serial_number")
                        or obj.get("chassis_serial_number")
                        or (obj.get("hardware_info") or {}).get("serial_number")
                        or _rfind(obj, {"serial_number", "chassis_serial_number"})
                    )
                    # model candidates
                    mdl = (
                        obj.get("product_name")
                        or obj.get("platform_name")
                        or obj.get("platform_type")
                        or obj.get("model")
                        or obj.get("sku")
                        or obj.get("product_id")
                        or _rfind(obj, {"product_name","platform_name","platform_type","model","sku","product_id"})
                    )
                    # prefer model first if requested
                    if model_first and mdl and not model_out:
                        model_out = str(mdl)
                    if sn and not serial_out:
                        serial_out = str(sn)
                    if (not model_first) and mdl and not model_out:
                        model_out = str(mdl)
                    if serial_out and model_out:
                        break
                except Exception:
                    continue
            return serial_out, model_out

        # ---- 1) /system (merge configuration/status/properties) ----
        sys_raw = self._get_json(
            f"{self.base}/system",
            params={"selector": "configuration,status,properties"},
            default={}
        ) or {}
        sysobj = _merge_views(sys_raw)

        # hostname
        facts["hostname"] = (
            sysobj.get("hostname")
            or sysobj.get("system_name")
            or sysobj.get("name")
            or _rfind(sysobj, {"hostname", "system_name", "name"})
        )

        # model (first pass)
        facts["model"] = (
            sysobj.get("platform_name")
            or sysobj.get("platform_type")
            or sysobj.get("product_name")
            or sysobj.get("model")
            or sysobj.get("sku")
            or sysobj.get("product_id")
            or _rfind(sysobj, {"platform_name","platform_type","product_name","model","sku","product_id"})
        )

        # os version
        sw = sysobj.get("software_info") or {}
        facts["os_version"] = sw.get("version") or sw.get("image_version")

        # serial (first pass)
        serial = (
            sysobj.get("serial_number")
            or sysobj.get("chassis_serial_number")
            or (sysobj.get("hardware_info") or {}).get("serial_number")
            or _rfind(sysobj, {"serial_number","chassis_serial_number"})
        )
        if serial:
            facts["serial_number"] = str(serial)

        # uptime
        uptime = _rfind(sysobj, {"time_since_boot","uptime","system_uptime","seconds_since_boot","up_time"})
        try:
            uptime = int(uptime) if uptime is not None else 0
        except Exception:
            uptime = 0
        if not uptime:
            cur = _rfind(sysobj, {"current_time","time_now","system_time"})
            boot = _rfind(sysobj, {"boot_time","last_boot_time"})
            ce, be = _to_epoch(cur), _to_epoch(boot)
            if ce is not None and be is not None and ce >= be:
                uptime = ce - be
        if not uptime:
            sys_status = self._get_json(f"{self.base}/system", params={"selector": "status"}, default={}) or {}
            u2 = _rfind(sys_status, {"time_since_boot","uptime","system_uptime","seconds_since_boot"})
            try:
                uptime = int(u2) if u2 is not None else 0
            except Exception:
                uptime = 0
        facts["uptime"] = max(0, int(uptime or 0))

        # ---- 2) Fallbacks for hostname/model/serial if still missing ----
        if not facts["hostname"]:
            sys_cfg_only = self._get_json(f"{self.base}/system", params={"selector": "configuration"}, default={}) or {}
            sys_cfg_only = _merge_views(sys_cfg_only)
            facts["hostname"] = (
                sys_cfg_only.get("hostname")
                or sys_cfg_only.get("system_name")
                or _rfind(sys_cfg_only, {"hostname", "system_name"})
                or self.hostname
            )

        # ---- 2) Asset endpoint (often has product_name & serial) ----
        asset = self._get_json(f"{self.base}/system/asset", default={}) or {}
        if not facts["model"]:
            facts["model"] = asset.get("product_name") or asset.get("sku") or asset.get("model")
        if not facts["serial_number"]:
            sn = asset.get("serial_number")
            if sn:
                facts["serial_number"] = str(sn)

        # ---- 3) Chassis map first (common place), then all subsystems ----
        if not (facts["serial_number"] and facts["model"]):
            ch_map = self._get_json(f"{self.base}/system/subsystems/chassis", default={}) or {}
            if isinstance(ch_map, dict):
                for _, ref in ch_map.items():
                    try:
                        ch = self._get_json(f"https://{self.hostname}{ref}", default={}) or {}
                        if not facts["serial_number"]:
                            sn = (
                                ch.get("serial_number")
                                or ch.get("chassis_serial_number")
                                or (ch.get("hardware_info") or {}).get("serial_number")
                                or _rfind(ch, {"serial_number","chassis_serial_number"})
                            )
                            if sn:
                                facts["serial_number"] = str(sn)
                        if not facts["model"]:
                            mdl = (
                                ch.get("product_name")
                                or ch.get("platform_name")
                                or ch.get("platform_type")
                                or ch.get("model")
                                or ch.get("sku")
                            )
                            if mdl:
                                facts["model"] = str(mdl)
                        if facts["serial_number"] and facts["model"]:
                            break
                    except Exception:
                        continue

        if not facts["model"] or not facts["serial_number"]:
            sn2, mdl2 = _scan_all_subsystems(model_first=True)
            if not facts["serial_number"] and sn2:
                facts["serial_number"] = sn2
            if not facts["model"] and mdl2:
                facts["model"] = mdl2

        # ---- 4) Firmware fallback for version ----
        if not facts["os_version"]:
            fw = self._get_json(f"{self.base}/firmware", default={}) or {}
            facts["os_version"] = fw.get("current_version") or fw.get("primary_version")

        # ---- 5) Interface list ----
        iface_map = self._get_json(f"{self.base}/system/interfaces", default={}) or {}
        if isinstance(iface_map, dict):
            facts["interface_list"] = sorted([k for k in iface_map.keys() if not str(k).startswith("_")])

        #self._trace("get_facts", facts)
        return facts


    # ----------------------------- interfaces ----------------------------

    def _iter_interfaces(self):
        iface_map = self._get_json(f"{self.base}/system/interfaces", default={}) or {}
        if not isinstance(iface_map, dict):
            return
        for name in sorted([k for k in iface_map.keys() if not str(k).startswith("_")]):
            yield name

    def get_interfaces(self):
        """
        Per-interface info with safe types:
          is_up(bool), is_enabled(bool), description(str), mac_address(str),
          speed(float Mbps), mtu(int), last_flapped(float seconds)
        """
        results = {}

        def _to_mbps(v):
            if v is None:
                return 0
            if isinstance(v, (int, float, bool)):
                return _to_int(v, 0)
            s = str(v).strip().lower()
            if s in ("", "auto", "unknown", "n/a", "na"):
                return 0
            try:
                if s.endswith("g"):  # "1g"
                    return int(float(s[:-1]) * 1000)
                if s.endswith("m"):  # "100m"
                    return int(float(s[:-1]))
                return int(float(s))  # plain number string -> Mbps
            except Exception:
                return 0

        def _first(d, *keys):
            for k in keys:
                if isinstance(d, dict) and k in d and d[k] not in (None, ""):
                    return d[k]
            return None

        # ---- 0) list interface names ----
        iface_map = self._get_json(f"{self.base}/system/interfaces", default={}) or {}
        names = sorted([k for k in iface_map.keys() if isinstance(k, str) and not k.startswith("_")])
        if not names:
            self._trace("get_interfaces", results)
            return results

        # ---- 1) bulk-pull interface attributes (fast + stable) ----
        # Aruba docs show using attributes for admin/link (and more). 
        # Ref: GET .../system/interfaces?depth=2&attributes=name,ipv4_address,admin_state,link_state etc.
        # (AOS-CX 10.13 REST API Guide, "GET method parameters" + examples) 
        attrs_if = "name,admin_state,link_state,description,mac,mac_address,ip_mtu,mtu,speed,link_speed,user_config"
        bulk_if = self._get_json(
            f"{self.base}/system/interfaces",
            params={"depth": 2, "attributes": attrs_if},
            default={}
        ) or {}

        # Normalize bulk_if to a dict: {ifname: {attrs...}}
        def _normalize_bulk(obj):
            out = {}
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, dict):
                        out[k] = v
            return out

        bulk_if = _normalize_bulk(bulk_if)

        # ---- 2) bulk-pull port status for physicals (admin/link often here) ----
        attrs_pt = "admin,admin_state,link_state,oper_state,oper_status,link_status,link_up,is_port_up,mac,mtu,speed,link_speed"
        bulk_pt = self._get_json(
            f"{self.base}/system/ports",
            params={"depth": 2, "attributes": attrs_pt},
            default={}
        ) or {}
        bulk_pt = _normalize_bulk(bulk_pt)

        # ---- 3) build per-interface result ----
        import re as _re
        phys_pat = _re.compile(r"^\d+/\d+/\d+$")  # e.g., "1/1/1"

        for name in names:
            try:
                i = bulk_if.get(name, {}) or {}
                p = bulk_pt.get(name, {}) if phys_pat.match(name) else {}

                # Some builds keep admin under user_config.admin (documented)
                # Ref: 10.13 Guide "writable selector" example shows "user_config": {"admin": "up"}.
                user_cfg = i.get("user_config") if isinstance(i.get("user_config"), dict) else {}

                # admin state
                admin = (
                    _first(p, "admin", "admin_state") or
                    _first(i, "admin", "admin_state") or
                    user_cfg.get("admin")
                )
                # Some expose "shutdown": True => disabled
                if admin is None and "shutdown" in i:
                    try: admin = not bool(i.get("shutdown"))
                    except Exception: pass
                if admin is None and "shutdown" in p:
                    try: admin = not bool(p.get("shutdown"))
                    except Exception: pass

                # oper/link state
                oper = (
                    _first(p, "oper_state", "oper_status", "link_state", "link_status", "link_up", "is_port_up") or
                    _first(i, "oper_state", "oper_status", "link_state", "link_status", "link_up", "is_port_up")
                )

                # text fields
                descr = i.get("description") or ""
                mac   = _first(i, "mac", "mac_address") or _first(p, "mac") or ""

                # numeric fields
                speed = _to_mbps(_first(p, "speed", "link_speed") or _first(i, "speed", "link_speed"))
                mtu   = _to_int(_first(i, "mtu", "ip_mtu") or _first(p, "mtu"), 0)

                results[name] = {
                    "is_up": _truthy(oper),
                    "is_enabled": _truthy(admin),
                    "description": str(descr),
                    "last_flapped": 0.0,   # CX doesn't expose a consistent flaps counter in REST
                    "speed": float(speed),
                    "mac_address": str(mac),
                    "mtu": int(mtu),
                }
            except Exception:
                results[name] = {
                    "is_up": False,
                    "is_enabled": False,
                    "description": "",
                    "last_flapped": 0.0,
                    "speed": 0.0,
                    "mac_address": "",
                    "mtu": 0,
                }

        self._trace("get_interfaces", results)
        return results

    def _interfaces_ip_bulk(self):
        """Internal cache layer for get_interfaces_ip()."""
        if getattr(self, "_if_ip_cache", None) is not None:
            return self._if_ip_cache
        self._if_ip_cache = self.get_interfaces_ip()
        return self._if_ip_cache

    def _detect_management_source_interface(self):
        """
        Look for 'ip source-interface ... interface <NAME>' in running-config JSON.
        Returns e.g. 'vlan1200' or None.
        """
        try:
            cfg = self._get_json(f"{self.base}/fullconfigs/running-config", default={}) or {}

            def walk(o):
                if isinstance(o, dict):
                    for key in ("source-interface", "source_interface", "ip_source_interface"):
                        if key in o:
                            v = o[key]
                            if isinstance(v, dict):
                                cand = None
                                if isinstance(v.get("all"), dict):
                                    cand = v["all"].get("interface") or v["all"].get("name")
                                cand = cand or v.get("interface") or v.get("name")
                                if isinstance(cand, str) and cand.strip():
                                    return cand.strip()
                    for val in o.values():
                        r = walk(val)
                        if r:
                            return r
                if isinstance(o, list):
                    for val in o:
                        r = walk(val)
                        if r:
                            return r
                if isinstance(o, str) and "source-interface" in o:
                    m = re.search(r"ip\s+source-interface\s+(?:all|\S+)\s+interface\s+(\S+)", o, re.IGNORECASE)
                    if m:
                        return m.group(1)
                return None

            found = walk(cfg)
            if isinstance(found, str) and found.strip():
                return found.lower().replace(" ", "")
        except Exception:
            pass
        return None

    def _pick_management_endpoint_with_prefix(self, ifip):
        """
        Decide management endpoint from interface addresses.
        Returns (ifname, ip, prefix_len, family: 'ipv4'|'ipv6') or (None,None,None,None).

        Preference:
          1) running-config 'ip source-interface ... interface <IF>'
          2) if self.hostname is an IP, match that exact IP to an interface
          3) SVI (name starts with vlan*) IPv4
          4) first non-link-local IPv4
          5) first global IPv6
        """
        import ipaddress

        def norm(s): return (s or "").lower().replace(" ", "")

        def find_on(ifname):
            addrs = ifip.get(ifname) or {}
            v4 = addrs.get("ipv4") or {}
            for ip, meta in v4.items():
                if not (ip.startswith("169.254.") or ip.startswith("127.") or ip == "0.0.0.0"):
                    plen = _to_int((meta or {}).get("prefix_length"), 0)
                    return ifname, ip, plen if plen else 0, "ipv4"
            v6 = addrs.get("ipv6") or {}
            for ip, meta in v6.items():
                if not ip.lower().startswith("fe80:"):
                    plen = _to_int((meta or {}).get("prefix_length"), 64)
                    return ifname, ip, plen if plen else 64, "ipv6"
            return None, None, None, None

        # 1) from running-config
        try:
            si = self._detect_management_source_interface()
            if si:
                key = norm(si)
                for ifn in ifip.keys():
                    if norm(ifn) == key:
                        r = find_on(ifn)
                        if r[0]:
                            return r
        except Exception:
            pass

        # 2) match the session's host IP to an interface address
        try:
            sess_ip = str(ipaddress.ip_address(self.hostname))
            for ifn, addrs in ifip.items():
                if sess_ip in (addrs.get("ipv4") or {}) or sess_ip in (addrs.get("ipv6") or {}):
                    # pick its stored prefix
                    meta = (addrs.get("ipv4") or {}).get(sess_ip) or (addrs.get("ipv6") or {}).get(sess_ip) or {}
                    fam = "ipv4" if "." in sess_ip else "ipv6"
                    plen = _to_int(meta.get("prefix_length"), 0 if fam == "ipv4" else 64)
                    return ifn, sess_ip, plen, fam
        except Exception:
            pass

        # 3) prefer SVI (vlan*)
        for ifn in sorted(ifip.keys()):
            if ifn.lower().startswith("vlan"):
                r = find_on(ifn)
                if r[0]:
                    return r

        # 4) any IPv4
        for ifn in sorted(ifip.keys()):
            r = find_on(ifn)
            if r[0]:
                return r

        return None, None, None, None


    def _pick_management_endpoint(self, ifip):
        """
        Decide management endpoint from interface addresses.
        Returns (mgmt_ifname, mgmt_ip) or (None, None).

        Preference:
          0) optional_args['mgmt_source_interface'] if set
          1) running-config 'ip source-interface ... interface <IF>'
          2) If self.hostname is an IP, pick the interface that has that exact IP
          3) members of VRF 'mgmt'
          4) preferred names (mgmt/oobm/management)
          5) first usable IPv4 anywhere
          6) first global IPv6
        """
        import ipaddress

        def norm(s): return (s or "").lower().replace(" ", "")

        def find_on(ifname):
            addrs = ifip.get(ifname) or {}
            for ip in (addrs.get("ipv4") or {}):
                if not (ip.startswith("169.254.") or ip.startswith("127.") or ip == "0.0.0.0"):
                    return ifname, ip
            for ip in (addrs.get("ipv6") or {}):
                if not ip.lower().startswith("fe80:"):
                    return ifname, ip
            return None, None

        # 0) explicit override
        try:
            src_if = (self.optional_args or {}).get("mgmt_source_interface")
        except Exception:
            src_if = None
        if src_if:
            key = norm(src_if)
            for ifn in ifip.keys():
                if norm(ifn) == key:
                    r = find_on(ifn)
                    if r[0]:
                        return r

        # 1) from running-config
        si = self._detect_management_source_interface()
        if si:
            key = norm(si)
            for ifn in ifip.keys():
                if norm(ifn) == key:
                    r = find_on(ifn)
                    if r[0]:
                        return r

        # 2) match the session's host IP to an interface address
        try:
            sess_ip = str(ipaddress.ip_address(self.hostname))
            for ifn, addrs in ifip.items():
                if sess_ip in (addrs.get("ipv4") or {}) or sess_ip in (addrs.get("ipv6") or {}):
                    return ifn, sess_ip
        except Exception:
            pass

        # 3) VRF 'mgmt' members
        try:
            vrfs = self._get_json(f"{self.base}/system/vrfs", default={}) or {}
            for name, ref in vrfs.items():
                if isinstance(name, str) and name.lower() == "mgmt":
                    vobj = self._get_json(f"https://{self.hostname}{ref}", default={}) or {}
                    members = list((vobj.get("interfaces") or {}).keys()) if isinstance(vobj.get("interfaces"), dict) else []
                    for ifn in members:
                        r = find_on(ifn)
                        if r[0]:
                            return r
        except Exception:
            pass

        # 4) preferred interface names
        for pref in ("mgmt", "oobm", "management", "mgmt0", "me0", "fxp0"):
            for ifn in ifip.keys():
                if norm(ifn) == pref:
                    r = find_on(ifn)
                    if r[0]:
                        return r

        # 5) first usable IPv4 anywhere
        for ifn in sorted(ifip.keys()):
            r = find_on(ifn)
            if r[0]:
                return r

        return None, None

    # Optional: keep old API for any callers using it
    def _pick_management_ip(self, ifip):
        _, ip = self._pick_management_endpoint(ifip)
        return ip


    def get_interfaces_counters(self):
        if self.skip_counters:
            self._trace("get_interfaces_counters", {})
            return {}

        counters = {}
        fields = (
            "rx_octets","tx_octets","rx_unicast","tx_unicast","rx_multicast","tx_multicast",
            "rx_broadcast","tx_broadcast","rx_discards","tx_discards","rx_errors","tx_errors",
            "rx_crc_errors","collisions"
        )
        for name in self._iter_interfaces():
            url = f"{self.base}/system/interfaces/{urllib.parse.quote(name, safe='')}"
            data = self._get_json(url, params={"selector": "status"}, default={}) or {}
            entry = {}
            for f in fields:
                entry[f] = _to_int(data.get(f), 0)
            counters[name] = entry

        self._trace("get_interfaces_counters", counters)
        return counters

    # --------------------------- interface IPs ---------------------------

    def get_interfaces_ip(self):
        """
        Return per-interface IPv4/IPv6 addresses in NAPALM format:
          { "<if>": { "ipv4": {ip: {"prefix_length": n}}, "ipv6": {...} } }
        Robust to AOS-CX variants: ip4_address/ip6_address, ipv4_address/ipv6_address,
        ip_address/ip_addresses, ipv4/ipv6 dicts/lists.
        """
        out = {}

        # Ask for ALL likely keys (note: ip4_address/ip6_address are the big ones on CX)
        attrs = (
            "name,ip4_address,ip6_address,ipv4_address,ipv6_address,"
            "ip_address,ip_addresses,ipv4,ipv6,primary_ip4,primary_ipv4,primary_ip6,primary_ipv6"
        )
        bulk = self._get_json(
            f"{self.base}/system/interfaces",
            params={"depth": 2, "attributes": attrs},
            default={}
        ) or {}

        def add_v4(dst, v):
            if isinstance(v, str) and "/" in v and ":" not in v:
                ip, plen = v.split("/", 1)
                dst.setdefault("ipv4", {})[ip] = {"prefix_length": _to_int(plen, 0)}

        def add_v6(dst, v):
            if isinstance(v, str) and ":" in v:
                if "/" in v:
                    ip, plen = v.split("/", 1)
                else:
                    ip, plen = v, "64"
                dst.setdefault("ipv6", {})[ip] = {"prefix_length": _to_int(plen, 64)}

        def harvest(entry, data):
            # strings
            add_v4(entry, data.get("ip4_address"))
            add_v6(entry, data.get("ip6_address"))
            add_v4(entry, data.get("ipv4_address"))
            add_v6(entry, data.get("ipv6_address"))
            add_v4(entry, data.get("primary_ip4") or data.get("primary_ipv4"))
            add_v6(entry, data.get("primary_ip6") or data.get("primary_ipv6"))

            # dict/list forms (ipv4/ipv6/ip_address/es)
            for key in ("ipv4", "ip_addresses", "ip_address"):
                v = data.get(key)
                if isinstance(v, dict):
                    for k in list(v.keys()):
                        if isinstance(k, str) and "/" in k and ":" not in k:
                            add_v4(entry, k)
                elif isinstance(v, list):
                    for k in v:
                        if isinstance(k, str) and "/" in k and ":" not in k:
                            add_v4(entry, k)

            v6 = data.get("ipv6")
            if isinstance(v6, dict):
                for k in list(v6.keys()):
                    if isinstance(k, str) and ":" in k:
                        add_v6(entry, k)
            elif isinstance(v6, list):
                for k in v6:
                    if isinstance(k, str) and ":" in k:
                        add_v6(entry, k)

        # 1) Bulk harvest
        if isinstance(bulk, dict):
            for ifname, data in bulk.items():
                if not isinstance(data, dict) or str(ifname).startswith("_"):
                    continue
                entry = {}
                harvest(entry, data)
                if entry:
                    out[ifname] = entry

        # 2) Fallback per-interface (for any interface still missing)
        missing = [n for n in (bulk.keys() if isinstance(bulk, dict) else []) if n not in out]
        if not missing:
            # Also include any interfaces not present in bulk (paranoia)
            iface_map = self._get_json(f"{self.base}/system/interfaces", default={}) or {}
            missing = [k for k in iface_map.keys() if k not in out and not str(k).startswith("_")]

        for name in sorted(missing):
            url = f"{self.base}/system/interfaces/{urllib.parse.quote(name, safe='')}"
            cfg = self._get_json(url, params={"selector": "configuration"}, default={}) or {}
            if isinstance(cfg, dict) and "configuration" in cfg and isinstance(cfg["configuration"], dict):
                cfg = cfg["configuration"]
            entry = {}
            harvest(entry, cfg or {})
            if entry:
                out[name] = entry

        self._trace("get_interfaces_ips", out)
        return out


    # ------------------------------ LLDP --------------------------------

    def get_lldp_neighbors(self):
        neighbors = {}
        return neighbors
        data = self._get_json(f"{self.base}/system/lldp/neighbors", default=None)
        if isinstance(data, dict) and data:
            for _, ref in data.items():
                try:
                    ninfo = self._get_json(f"https://{self.hostname}{ref}", default={}) or {}
                    local = ninfo.get("local_port") or ninfo.get("local_interface") or ""
                    if not local:
                        continue
                    rem_name = (
                        ninfo.get("system_name")
                        or ninfo.get("chassis_name")
                        or ninfo.get("chassis_id")
                        or "unknown"
                    )
                    rem_port = ninfo.get("port_id") or ninfo.get("port_description") or "unknown"
                    neighbors.setdefault(local, []).append({"hostname": str(rem_name), "port": str(rem_port)})
                except Exception:
                    continue
            return neighbors

        intf_map = self._get_json(f"{self.base}/system/lldp/interfaces", default={}) or {}
        if isinstance(intf_map, dict):
            for local, ref in intf_map.items():
                try:
                    url = f"https://{self.hostname}{ref}/neighbors"
                    nmap = self._get_json(url, default={}) or {}
                    if isinstance(nmap, dict):
                        for _, nref in nmap.items():
                            ninfo = self._get_json(f"https://{self.hostname}{nref}", default={}) or {}
                            rem_name = (
                                ninfo.get("system_name")
                                or ninfo.get("chassis_name")
                                or ninfo.get("chassis_id")
                                or "unknown"
                            )
                            rem_port = ninfo.get("port_id") or ninfo.get("port_description") or "unknown"
                            neighbors.setdefault(local, []).append(
                                {"hostname": str(rem_name), "port": str(rem_port)}
                            )
                except Exception:
                    continue
        self._trace("get_lddp", neighbors)
        return neighbors

    # ------------------------------- VLANs -------------------------------

    def get_vlans(self):
        """
        Return VLANs in NAPALM format with **integer** keys only.
        """
        vlans = {}
        coll = self._get_json(f"{self.base}/system/vlans", default={}) or {}
        if not isinstance(coll, dict) or not coll:
            return vlans

        for key, ref in coll.items():
            if isinstance(ref, str) and ref.startswith("/"):
                detail = self._get_json(f"https://{self.hostname}{ref}", default={}) or {}
            elif isinstance(ref, dict) and ref:
                detail = ref
            else:
                detail = self._get_json(
                    f"{self.base}/system/vlans/{urllib.parse.quote(str(key), safe='')}",
                    default={}
                ) or {}

            # derive VLAN ID robustly
            vid = (detail.get("vlan_id") or detail.get("id") or
                   detail.get("vlan_tag") or detail.get("vid"))
            if isinstance(vid, str) and vid.isdigit():
                vid = int(vid)
            elif isinstance(vid, (int, float)):
                vid = int(vid)
            else:
                m = re.search(r"(\d+)$", str(key))
                vid = int(m.group(1)) if m else None

            if vid is None:
                # drop anything we can't coerce to int to avoid None > int in clients
                continue

            name = (detail.get("name") or detail.get("display_name") or f"VLAN{vid}")

            ifaces = []
            for cand in ("interfaces", "ports", "port_members"):
                val = detail.get(cand)
                if isinstance(val, list):
                    ifaces = [str(x) for x in val if isinstance(x, (str, int))]
                    break

            vlans[int(vid)] = {"name": str(name), "interfaces": ifaces}
        self._trace("get_vlans", vlans)
        return vlans

    # -------------------------- safe empty stubs -------------------------

    def get_arp_table(self, vrf=""):
        # Return an empty list rather than None; clients iterate safely.
        self._trace("get_arp_table", "")
        return []

    def get_mac_address_table(self):
        # Return an empty list rather than None; clients iterate safely.
        self._trace("get_mac_address_table", "")
        return []


