# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# pycomm3's LogixDriver against the server role with its own tag upload:
# init_tags=True makes it browse the Symbol object (controller and
# program scope), read every structure's template, then read and write
# tags by symbol instance. Prints "PEER <step> <json>" lines and
# "PEER done".
#
#   python browse.py <host:port[/route]>

import json
import sys
import traceback

from pycomm3 import LogixDriver


def say(step, obj=None):
    print("PEER " + step + ("" if obj is None else " " + json.dumps(obj, sort_keys=True, default=str)), flush=True)


def tag(t):
    return {"tag": t.tag, "value": t.value, "type": t.type, "error": t.error}


try:
    with LogixDriver(sys.argv[1], init_tags=True, init_program_tags=True) as plc:
        say("tags", sorted(plc.tags.keys()))
        motor = plc.data_types.get("Motor", {})
        say("motor", {"attributes": motor.get("attributes"), "size": motor.get("template", {}).get("structure_size")})
        say("string", plc.data_types.get("STRING", {}).get("string"))
        say("instance-ids", plc._cfg.get("use_instance_ids"))
        say("read", [tag(t) for t in plc.read("Pump", "Pump.Speed", "Title", "Program:Main.Count", "Levels{10}")])
        say("write", [tag(t) for t in plc.write(("Pump.Speed", 99.5), ("Pump.Fault", True), ("Title", "Renamed line"),
                                                  ("Program:Main.Count", 43))])
        say("reread", [tag(t) for t in plc.read("Pump", "Title", "Program:Main.Count")])
        say("readonly", tag(plc.write("Locked", 5)))
except Exception:
    say("error", traceback.format_exc())
say("done")
