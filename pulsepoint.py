import base64
import configparser
import hashlib
import json
import re
import sys
import threading
import time
import traceback
import urllib
import urllib.request
from socket import gaierror
from string import capwords

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import stickybot110 as stickybot

# I used portions of code from Davnit's pulse.py file (specifically, the
# decryption routines.)
# https://gist.github.com/Davnit/4d1ccdf6c674ce9172a251679cd0960a
# If you think this code is worth a star, give Davnit's code a star too since
# without it, this wouldn't have been possible. 

VERSION = 0x0101

re_TO_CAP = re.compile(r"(.*)(, CA)$")

CALL_TYPES = {
    "AA": "Auto Aid",
    "MU": "Mutual Aid",
    "ST": "Strike Team/Task Force",
    "AC": "Aircraft Crash",
    "AE": "Aircraft Emergency",
    "AES": "Aircraft Emergency Standby",
    "LZ": "Landing Zone",
    "AED": "AED Alarm",
    "OA": "Alarm",
    "CMA": "Carbon Monoxide",
    "FA": "Fire Alarm",
    "MA": "Manual Alarm",
    "SD": "Smoke Detector",
    "TRBL": "Trouble Alarm",
    "WFA": "Waterflow Alarm",
    "FL": "Flooding",
    "LR": "Ladder Request",
    "LA": "Lift Assist",
    "PA": "Police Assist",
    "PS": "Public Service",
    "SH": "Sheared Hydrant",
    "EX": "Explosion",
    "PE": "Pipeline Emergency",
    "TE": "Transformer Explosion",
    "AF": "Appliance Fire",
    "CHIM": "Chimney Fire",
    "CF": "Commercial Fire",
    "WSF": "Confirmed Structure Fire",
    "WVEG": "Confirmed Vegetation Fire",
    "CB": "Controlled Burn/Prescribed Fire",
    "ELF": "Electrical Fire",
    "EF": "Extinguished Fire",
    "FIRE": "Fire",
    "FULL": "Full Assignment",
    "IF": "Illegal Fire",
    "MF": "Marine Fire",
    "OF": "Outside Fire",
    "PF": "Pole Fire",
    "GF": "Refuse/Garbage Fire",
    "RF": "Residential Fire",
    "SF": "Structure Fire",
    "VEG": "Vegetation Fire",
    "VF": "Vehicle Fire",
    "WCF": "Working Commercial Fire",
    "WRF": "Working Residential Fire",
    "BT": "Bomb Threat",
    "EE": "Electrical Emergency",
    "EM": "Emergency",
    "ER": "Emergency Response",
    "GAS": "Gas Leak",
    "HC": "Hazardous Condition",
    "HMR": "Hazmat Response",
    "TD": "Tree Down",
    "WE": "Water Emergency",
    "AI": "Arson Investigation",
    "HMI": "Hazmat Investigation",
    "INV": "Investigation",
    "OI": "Odor Investigation",
    "SI": "Smoke Investigation",
    "LO": "Lockout",
    "CL": "Commercial Lockout",
    "RL": "Residential Lockout",
    "VL": "Vehicle Lockout",
    "IFT": "Interfacility Transfer",
    "ME": "Medical Emergency",
    "MCI": "Multi Casualty",
    "EQ": "Earthquake",
    "FLW": "Flood Warning",
    "TOW": "Tornado Warning",
    "TSW": "Tsunami Warning",
    "CA": "Community Activity",
    "FW": "Fire Watch",
    "NO": "Notification",
    "STBY": "Standby",
    "TEST": "Test",
    "TRNG": "Training",
    "UNK": "Unknown",
    "AR": "Animal Rescue",
    "CR": "Cliff Rescue",
    "CSR": "Confined Space",
    "ELR": "Elevator Rescue",
    "RES": "Rescue",
    "RR": "Rope Rescue",
    "TR": "Technical Rescue",
    "TNR": "Trench Rescue",
    "USAR": "Urban Search and Rescue",
    "VS": "Vessel Sinking",
    "WR": "Water Rescue",
    "TCE": "Expanded Traffic Collision",
    "RTE": "Railroad/Train Emergency",
    "TC": "Traffic Collision",
    "TCS": "Traffic Collision Involving Structure",
    "TCT": "Traffic Collision Involving Train",
    "WA": "Wires Arcing",
    "WD": "Wires Down"
}

UNIT_STATUS = {
    "DP":"Dispatched",
    "AK":"Acknowledged",
    "ER":"En Route",
    "OS":"On Scene",
    "TR":"Transporting",
    "TA":"Transport Arrived",
    "AQ":"Available in Quarters",
    "AR":"Available on Radio",
    "AE":"Available on Scene"
}

ON_SCENE = {"OS", "AE"}
ASSIGNED = {"DP", "AK", "ER", "OS", "TR", "TA", "AE"}

CFG_DEFAULT = {
    "IRC": {
        "server":"127.0.0.1",
        "port":"6667",
        "nick":"PulsePoint",
        "channel":"#fire, #pulsepoint-relay",
        "trigger":"!",
        "welcome":"PulsePoint Relay v{:X}.{:02X}!".format(VERSION >> 8,
                                                          VERSION & 0xff),
        "cmd_success":"Success!",
        "cmd_fail":"Fail!"
    }
}


def relevant2(inc):
    if inc.alarm_level != None:
        try:
            if int(inc.alarm_level) > 1: return True
        except: pass
    if inc.call_type in ["ST", "AE", "AES", "AC", "EX", "PE",
                         "SF", "VEG", "WSF", "WVEG", "CF", "RF", "WCF", "WRF",
                         "HMR", "TOW", "TSW", "EQ", "TR", "WR", "TCT"]:
        return True
    return False

def un_ts(ts):
    if not ts: return float(int(time.time()))
    return time.mktime(time.strptime(ts.replace("Z", "UTC"),
                                                "%Y-%m-%dT%H:%M:%S%Z"))

def try_float(f):
    try: return float(f)
    except: return 0.

def main():
    data = json.loads(request.urlopen(\
        "https://web.pulsepoint.org/DB/giba.php?agency_id=LAC01"\
        .read().decode()))
    ct = base64.b64decode(data.get("ct"))
    iv = bytes.fromhex(data.get("iv"))
    salt = bytes.fromhex(data.get("s"))
    hasher = hashlib.md5()
    key = b''
    block = None
    cp = configparser.RawConfigParser()
    cp.read("watcher.ini")
    while len(key) < 32:
        if block:
            hasher.update(block)
        hasher.update(cp["PulsePoint"]["password"].encode("ascii", "ignore"))
        hasher.update(salt)
        block = hasher.digest()
        hasher = hashlib.md5()
        key += block
    # Create a cipher and decrypt the data
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    out = decryptor.update(ct) + decryptor.finalize()
    # Clean up output data
    out = out[1:out.rindex(b'"')].decode() # Strip off extra bytes and quotes
    out = out.replace(r'\"', r'"')         # Un-escape quotes
    data = json.loads(out)
    active = data.get("incidents", {}).get("active", {})
    [print("%s @ %s" % (c.get("PulsePointIncidentCallType"), \
                        c.get("FullDisplayAddress"))) for c in active]

def form_agency_update(upd):
    if not upd: return
    for inc in filter(relevant, upd.new_incs):
        print("New %s Incident" % upd.agency.name)
        inc.test()
        print()
    for inc in filter(relevant, upd.rem_incs):
        print("%s Incident Cleared: %s @ %s\n" % \
              (upd.agency.name,
               inc.ct(),
               inc.loc))
    for (inc, delta) in upd.chg_incs:
        if not relevant(inc): continue
        for pu in delta.list_changes():
            if inc.alarm_level != None: al = int(inc.alarm_level)+1
            else: al = 0
            print("Incident update for %s %s%s @ %s: %s was %s, now %s" \
                  % (upd.agency.name,
                     inc.ct(),
                     ("[%d-alarm] " % al if al else ""),
                     inc.loc,
                     pu[0],
                     pu[1],
                     pu[2]))
        if delta.new_units:
            print("%d %s unit%s added to %s @ %s:" % \
                  (len(delta.new_units),
                   upd.agency.name,
                   ("" if len(delta.new_units) == 1 else "s"),
                   inc.ct(),
                   inc.loc))
            for unit in delta.new_units:
                print(unit.test_str())
        if delta.rem_units:
            print("%s %s unit%s removed from %s @ %s:" % \
                  (str(inc.ct()),
                   inc.agency.name,
                   ("" if len(delta.rem_units) == 1 else "s"),
                   inc.loc))
            for unit in delta.rem_units:
                print("  %s" % unit.unit_id)
        for unit in delta.chg_units:
            print("%s %s for %s @ %s:  was %s, now %s" % \
                  (inc.agency.name,
                   unit.unit_id,
                   inc.ct(),
                   inc.loc,
                   unit.status_str(last=True),
                   unit.status_str(last=False)))
        if delta: print()


class PulsePoint(object):
    def __init__(self, agency_id, friendly_name=None, cfg_fn="watcher.ini"):
        cp = configparser.RawConfigParser()
        cp.read_dict(CFG_DEFAULT)
        cp.read(cfg_fn)
        self.password = cp["PulsePoint"]["password"].encode("ascii", "ignore")
        if isinstance(agency_id, int): agency_id = "%d" % agency_id
        self.id = agency_id
        if friendly_name: self.name = friendly_name
        else: self.name = agency_id
        self.active = dict()

    def get_incidents_raw(self):
        url = "https://web.pulsepoint.org/DB/giba.php?agency_id=%s" % \
              (self.id)
        try:
            ed = json.loads(urllib.request.urlopen(url).read().decode())
        except urllib.error.URLError:
            return
        except gaierror:
            return
        ct = base64.b64decode(ed.get("ct"))  # cipher text
        iv = bytes.fromhex(ed.get("iv")) # initialization vector
        s = bytes.fromhex(ed.get("s"))   # salt
        h = hashlib.md5()
        k = b''
        b = None
        while len(k) < 32:
            if b: h.update(b)
            h.update(self.password)
            h.update(s)
            b = h.digest()
            h = hashlib.md5()
            k += b
        d = Cipher(algorithms.AES(k), modes.CBC(iv), default_backend())\
            .decryptor()
        out = d.update(ct) + d.finalize()
        #                           remove excess data and un-escape quotes
        data = json.loads(out[1:out.rindex(b'"')].decode().replace(r'\"', r'"'))
        return data.get("incidents", {})

    def get_active_raw(self):
        raw = self.get_incidents_raw()
        if raw == None: return []
        return raw.get("active")

    def get_active(self):
        try:
            return set([Incident(self, d) for d in self.get_active_raw()])
        except TypeError: return

    def get_active_d(self):
        """Because some operations are easier using a dict? let's see."""
        d = dict()
        try:
            for inc_d in self.get_active_raw():
                inc = Incident(self, inc_d)
                d[inc.id] = inc
        except TypeError: return
        return d

    def update(self):
        """Refresh all the incidents with live data"""
        updo = AgencyUpdate(self)
        try: active = self.get_active()
        except gaierror: return # don't 'update' data if network is down
        if active == None: return
        for inc in active:
            if inc.id in self.active: # check if incident we already have
                inc_update = self.active[inc.id].update(inc)
                if inc_update:
                    updo.inc_changed(inc, inc_update)
            else: # otherwise, it's a new incident
                self.active[inc.id] = inc
                updo.inc_added(self.active[inc.id])
        # anything we have that they don't is a cleared incident
        for inc_id in set(self.active.keys()):
            if not any(map(lambda q:q.id == inc_id, active)):
                updo.inc_removed(self.active[inc_id])
                del self.active[inc_id]
        return updo

    def update2(self):
        """Refresh all the incidents with live data, testing dict"""
        updo = AgencyUpdate(self)
        try: active = self.get_active_d()
        except gaierror: return
        if active == None: return
        # what if we - gasp - fetched a dict instead of a list???
        for inc_id in active:
            inc = active[inc_id]
            if inc_id in self.active: # check if incident we already have
                inc_update = self.active[inc_id].update(inc)
                if inc_update:
                    updo.inc_changed(inc, inc_update)
            else: # otherwise, it's a new incident
                self.active[inc_id] = inc
                updo.inc_added(self.active[inc_id])
        # anything we have that they don't is a cleared incident
        rem_ids = self.active.keys() - active.keys()
        for inc_id in rem_ids:
            updo.inc_removed(self.active[inc_id])
            del self.active[inc_id]
        return updo

    def list_active(self):
        return sorted([self.active[inc_id] for inc_id in self.active],
                      key=lambda q:q.ts,
                      reverse=True)
    

class AgencyUpdate(object):
    def __init__(self, agency):
        self.agency = agency
        self.did_update = False
        self.new_incs = set()
        self.rem_incs = set()
        self.chg_incs = set()

    def __bool__(self):
        return self.did_update

    def inc_added(self, inc):
        self.did_update = True
        self.new_incs.add(inc)

    def inc_removed(self, inc):
        self.did_update = True
        self.rem_incs.add(inc)

    def inc_changed(self, inc, delta):
        self.did_update = True
        self.chg_incs.add((inc, delta))


class Incident(object):
    def __init__(self, agency, json_data):
##        self.raw = json_data
        self.id = json_data.get("ID", "0")
        self.lat = try_float(json_data.get("Latitude", 0))
        self.lon = try_float(json_data.get("Longitude", 0))
        self.agency_id = json_data.get("AgencyID", "?????") # remove later
        self.agency = agency
        self.call_type = json_data.get("PulsePointIncidentCallType", "UNK")
        self.loc_u = json_data.get("FullDisplayAddress", "Coords %.4f %.4f" % \
                                 (self.lat, self.lon))
        m = re_TO_CAP.match(self.loc_u)
        if m:
            self.loc = capwords(m.group(1))+m.group(2)
        else:
            self.loc = self.loc_u
        self.ts = un_ts(json_data.get("CallReceivedDateTime"))
        self.alarm_level = json_data.get("AlarmLevel")
        self.units = dict()
        for u in json_data.get("Unit", []):
            uid = u.get("UnitID", '?')
            self.units[uid] = (Unit(self.agency,
                                    uid,
                                    u.get("PulsePointDispatchStatus", "??")))

    def test(self):
        print("%s @ %s has %d units:" % (CALL_TYPES.get(self.call_type, "???"),
                                         self.loc,
                                         len(self.units)))
        for u in self.units:
            print(self.units[u].test_str())

    def __hash__(self):
        return hash(str(self.agency.id)+'-'+str(self.id))

    def on_scene(self):
        """Check if any units are active on scene"""
        return any(map(lambda q:self.units[q].status == "OS",
                       self.units.keys()))

    def ct(self):
        """Return formatted call type string"""
        return CALL_TYPES.get(self.call_type, "Unknown")

    def within(self, poly):
        """Check if incident is inside polygon"""
        return False # numpy polygon

    def update(self, other):
        """Update status and units and stuff"""
        if self.id != other.id or self.agency.id != other.agency.id:
            return {"ERR":"ERR", "changes":0}
        changes = 0
        upd = dict()
        updo = IncidentUpdate(self)
        for attr in ["lat", "lon", "call_type", "loc", "alarm_level"]:
            if getattr(self, attr) != getattr(other, attr):
                upd[attr] = getattr(self, attr)
                updo.register_change(attr, getattr(self, attr),
                                     getattr(other, attr))
                setattr(self, attr, getattr(other, attr))
                changes += 1
        u_chg = {}
        u_add = other.units.keys() - self.units.keys()
        u_rem = self.units.keys() - other.units.keys()
        u_chg = dict()
        changes += len(u_add)+len(u_rem)
        # this is really inefficient
        for uid in other.units:
            if uid in u_add: continue
            if self.units[uid].status == other.units[uid].status: continue
            u_chg[uid] = self.units[uid].status
            updo.unit_changed(uid, other.units[uid].status)
            changes += 1
        upd["u_add"] = u_add
        upd["u_rem"] = u_rem
        upd["u_chg"] = u_chg
        upd["changes"] = changes
        for u in u_rem: updo.unit_removed(u)
        self.units = other.units
        for u in u_add: updo.unit_added(u)
        return updo


class IncidentUpdate(object):
    """Storage class for incident updates, dicts are getting bad"""
    def __init__(self, inc):
        self.inc = inc
        self.did_change = False
        self.changes = {}
        self.new_units = set()
        self.rem_units = set()
        self.chg_units = set()

    def register_change(self, val, old, new):
        """Register change of parameter val from old to new"""
        self.changes[val] = (old, new)
        self.did_change = True

    def list_changes(self):
        """Return tuple of parameter changes"""
        return tuple(sorted([(k, self.changes[k][0], self.changes[k][1]) \
                             for k in self.changes]))

    def unit_added(self, uid):
        self.new_units.add(self.inc.units[uid])
        self.did_change = True

    def unit_removed(self, uid):
        """Register a removed unit before actually removing it"""
        self.rem_units.add(self.inc.units[uid])
        self.did_change = True

    def unit_changed(self, uid, new_status):
        u = self.inc.units[uid]
        u.update(new_status)
        self.chg_units.add(u)
        self.did_change = True

    def __bool__(self):
        return self.did_change
        
        


class Unit(object):
    def __init__(self, agency, unit_id, status="??"):
        self.agency = agency
        self.unit_id = str(unit_id)
        self.status = str(status)
        self.last_status = None

    def __hash__(self):
        return hash(self.agency.id+'.'+self.unit_id+'='+self.status)

    def on_scene(self):
        return self.status in ON_SCENE

    def test_prefix(self):
        if self.status in ON_SCENE: return "*"
        elif self.status in ASSIGNED: return ">"
        else: return " "

    def update(self, status):
        self.last_status = self.status
        self.status = status

    def test_str(self):
        return "  %s%s%s: %s" % \
               (self.test_prefix(),
                (self.agency.name+' ' if self.agency else ""),
                self.unit_id,
                self.status_str())

    def status_str(self, last=False):
        if last: s = self.last_status
        else: s = self.status
        return UNIT_STATUS.get(s, "Unknown")


class IRC(object):
    def __init__(self, cb, cfg_fn):
        if not cfg_fn: # no stickybot module loaded
            self.server = ""
            self.port = 6667
            self.nick = ""
            self.channel = ""
            self.stickybot = None
            return
        self.cb = cb
        cp = configparser.RawConfigParser()
        cp.read_dict(CFG_DEFAULT)
        cp.read(cfg_fn)
        self.server = cp["IRC"]["server"]
        self.port = cp.getint("IRC", "port")
        self.nick = cp["IRC"]["nick"]
        self.channel = list(map(lambda q:q.strip(),
                                cp["IRC"]["channel"].split(',')))
        self.welcome = cp["IRC"]["welcome"]
        self._success = cp["IRC"]["cmd_success"]
        self._fail = cp["IRC"]["cmd_fail"]
        self.cmd_trigger = cp["IRC"]["trigger"]
        self.send_rdy = threading.Event()
        self.send_rdy.set()
        self.stickybot = stickybot.Stickybot((self.server, int(self.port)),
                                             self.nick)
            
    def connect(self):
        print("Connecting to {s.server}:{s.port} as {s.nick}".format(s=self))
        self.stickybot.connect()
        while not self.stickybot.ready: time.sleep(0.001)
        print("Connected!")
        for channel in self.channel: self.stickybot.join(channel)
        self.cmd_buffer = []
        time.sleep(0.5) # give it time for the server to catch up
        if self.welcome:
            for channel in self.channel:
                self.stickybot.privmsg(channel, self.welcome)

    def do_stuff(self):
        line = self.stickybot.recv() # grab a line off the buffer
        if not line: return # since we're async, there's not always a line
        if line.printable: print(str(line)) # if it's not a control command
# (like a PRIVMSG you can see), then display a readable form of it

    def flush_incoming(self):
        if not self.stickybot: return
        while self.stickybot.recv(): pass

    def dump_incoming(self):
        if not self.stickybot: return []
        l = []
        while True:
            l.append(self.stickybot.recv())
            if not l[-1]: break
        return l[:-1]

    def send(self, msg):
        """Send a message to all joined channels. Used for broadcasts."""
        self.send_rdy.wait()
        self.send_rdy.clear()
        for channel in self.channel:
            self.stickybot.privmsg(channel, msg)
        self.send_rdy.set()

    def send_to(self, dst, msg):
        """Send a message to a particular destination. Used for commands."""
        self.send_rdy.wait()
        self.send_rdy.clear()
        self.stickybot.privmsg(dst, msg)
        self.send_rdy.set()

    def __bool__(self):
        return bool(self.stickybot)

    def get_commands(self):
        cmds = []
        in_cmd = self.dump_incoming()
        if in_cmd:
            for cmd in in_cmd:
                if not cmd.src or not cmd.msg: continue
##                print("COMMAND: "+repr(cmd.src)+" :: "+repr(cmd.msg))
                cmds.append((cmd.src, cmd.msg, cmd.channel))
        return cmds

    def loop(self):
        self.connect()
        self.running = True
        while self.running:
            try:
                cmds = self.get_commands()
                if not cmds:
                    time.sleep(0.005)
                    continue
                for cmd in cmds:
                    self.parse_cmd(cmd)
            except KeyboardInterrupt:
                self.cb.running = False
                self.running = False
            except:
                print("Incident Watcher encountered an error!")
                print(sys.exc_info()[0])
                print(sys.exc_info()[1])
                traceback.print_tb(sys.exc_info()[-1])
                self.send("\x0314\x1dWarning: Stickybot encountered \
an error. See console!\x1d\x0f")
                time.sleep(0.5)
        self.stickybot.disconnect()

    def parse_cmd(self, cmd):
        """cmd is tuple (stickybot.User, str msg, str channel)"""
        # much of this code came from another personal project of mine
        # so some parts may feel weird or different. 
        if not self.stickybot:
            print("PARSE_CMD: Unable to parse command due to IRC shutdown")
            return
        cmd_t = self.cmd_trigger # allow on-the-fly changes??
        if cmd[2] == self.stickybot.nick:
            # it's a private message
            dst = cmd[0].nick
            if dst == "__server" or '.' in dst or dst == self.stickybot.nick:
                return
            # allow non prefixed commands in privmsg
            if not cmd[1].startswith(cmd_t):
                cmd = list(cmd)
                cmd[1] = cmd_t + cmd[1]
                cmd = tuple(cmd)
        else: dst = cmd[2]
        if not cmd[1].startswith(cmd_t): return
        # ping command requires a little special treatment to preserve case
        if cmd[1].lower() == cmd_t+"ping":
            if cmd[1][2] == "I":
                self.send_to(dst, cmd[1].replace("I", "O")[1:])
            else:
                self.send_to(dst, cmd[1].replace("i", "o")[1:])
        msg = cmd[1].partition(cmd_t)[2]
        c_args = list(filter(None, msg.split(' ')))
        c_cmd = c_args.pop(0)
        print("Command is probably {:s} {:s} from {:s} in {:s}"\
              .format(c_cmd, repr(c_args), str(cmd[0]), cmd[2]))
        if not c_cmd: return
        poll_command = "cmd_{}".format(c_cmd)
        if hasattr(self, poll_command):
            try: getattr(self, poll_command)(*c_args, dst=dst)
            except:
                print("A command ({}) failed!".format(c_cmd))
                print(sys.exc_info()[:-1])
                traceback.print_tb(sys.exc_info()[-1])
                self.send_to(dst, self._fail)
        # assume everything after this is privileged
        # < check if user has permissions, else return > (not used here)
        poll_command = "pcmd_{}".format(c_cmd)
        if hasattr(self, poll_command):
            print("The command {} being run is privileged!".format(c_cmd))
            try: getattr(self, poll_command)(*c_args, dst=dst)
            except:
                print("A privileged command ({}) failed!".format(c_cmd))
                print(sys.exc_info())
                self.send_to(dst, self.fail)

    def cmd_version(self, *args, dst):
        self.send_to(dst, "PulsePoint Relay v%x.%02x, \
running on Stickybot %s and Python %d.%d.%d" % \
                  (VERSION >> 8,
                   VERSION & 0xFF,
                   stickybot.VERSION,
                   sys.version_info[0],
                   sys.version_info[1],
                   sys.version_info[2]))

    def cmd_ver(self, *args, dst):
        return self.cmd_version(*args, dst=dst)

    def cmd_listagencies(self, *args, dst):
        msg = []
        s = "I am following \x02%d\x02 agenc%s: "
        for i, agency in enumerate(list(self.cb.pp_agencies.keys())):
            if len(s) > 400 and i < len(self.cb.pp_agencies)-1:
                s += " ..."
                msg.append(s)
                s = "... "
            incs = self.cb.pp_agencies[agency].get_active()
            if not incs: incs = 0
            else: incs = len(list(filter(self.cb.printable, incs)))
            if incs == 0: incs = "\x1d0 incs\x1d"
            elif incs == 1: incs = "1 inc"
            else: incs = "%d incs" % incs
            s += "\x02%s\x02 (\x1d%s\x1d, %s); " % \
                 (agency, self.cb.pp_agencies[agency].name, incs)
        msg.append(s[:-2])
        if len(self.cb.pp_agencies) == 1: lm = "y"
        else: lm = "ies"
        msg[0] = msg[0] % (len(self.cb.pp_agencies), lm)
        for s in msg: self.send_to(dst, s)

    def cmd_la(self, *args, dst):
        return self.cmd_listagencies(*args, dst=dst)

    def cmd_laa(self, *args, dst):
        msg = []
        s = "I am following \x02%d\x02 active agenc%s: "
        ac = 0
        for i, agency in enumerate(list(self.cb.pp_agencies.keys())):
            if len(s) > 400 and i < len(self.cb.pp_agencies)-1:
                s += " ..."
                msg.append(s)
                s = "... "
            incs = self.cb.pp_agencies[agency].get_active()
            if not incs: incs = 0
            else: incs = len(list(filter(self.cb.printable, incs)))
            if incs == 0: continue
            elif incs == 1: incs = "1 inc"
            else: incs = "%d incs" % incs
            ac += 1
            s += "\x02%s\x02 (\x1d%s\x1d, %s); " % \
                 (agency, self.cb.pp_agencies[agency].name, incs)
        msg.append(s[:-2])
        if ac == 1: lm = "y"
        else: lm = "ies"
        msg[0] = msg[0] % (ac, lm)
        for s in msg: self.send_to(dst, s)

    def cmd_listincidents(self, *args, dst):
        if len(args) != 1: return
        args = [args[0].upper()]
        if args[0] not in self.cb.pp_agencies: return
        agency = self.cb.pp_agencies[args[0]]
        incs = agency.get_active()
        if not incs: incs = [] # maybe it's time to always return list type
        else: incs = list(filter(self.cb.printable, incs))
        if not incs:
            self.send_to(dst, "Agency \x02%s\x02 (\x1d%s\x1d) has no active \
incidents. See https://web.pulsepoint.org/?agencyid=%s" % \
                         (agency.id, agency.name, agency.id))
            return
        if len(incs) == 1: lm = ""
        else: lm = "s"
        self.send_to(dst, "Agency \x02%s\x02 (\x1d%s\x1d) has \x02%d\x02 active \
incident%s. See https://web.pulsepoint.org/?agencyid=%s" % \
                     (agency.id, agency.name, len(incs), lm, agency.id))
        for inc in incs:
            if len(inc.units) == 1: lm = ""
            else: lm = "s"
            self.send_to(dst, "- %s at %s with %s assigned unit%s \
(\x1did: %s\x1d)" % (inc.ct(), inc.loc, len(inc.units), lm, inc.id))

    def cmd_li(self, *args, dst):
        return self.cmd_listincidents(*args, dst=dst)
        


class IncidentWatcher(object):
    def __init__(self, cfg_fn="watcher.ini"):
        cp = configparser.RawConfigParser()
        cp.optionxform = str
        cp.read(cfg_fn)
        self.cfg_fn = cfg_fn
        self.agencies = dict(cp["Agencies"])
        self.pp_agencies = {k: PulsePoint(k, self.agencies[k],
                                          cfg_fn=self.cfg_fn) \
                            for k in self.agencies}
        self.update_timer = 30
        self.wait = 75
        self.incidents = {}
        self.pending = {}
        for k in self.agencies.keys():
            self.incidents[k] = set()
            self.pending[k] = set()
        self.iw_rdy = threading.Event()
        self.running = False
        self.irc = IRC(self, cfg_fn)
        self.irc_t = threading.Thread(target=self.irc.loop, daemon=True)
        self.irc_t.start()

    def loop(self):
        self.running = True
        for aid in self.pp_agencies:
            agency = self.pp_agencies[aid]
            self.handle_update(agency.update(), display=False)
##            [inc.test() for inc in filter(relevant, agency.list_active())]
            self.iw_rdy.set()
            time.sleep(0.5)
            self.iw_rdy.clear()
        i = 0
        akl = list(self.pp_agencies.keys())
        print("PulsePoint: New incidents now being collected.")
        while self.running:
            try:
                self.iw_rdy.set()
                for j in range(self.update_timer):
                    time.sleep(1./len(akl))
                self.iw_rdy.clear()
                upd = self.pp_agencies[akl[i]].update()
                self.handle_pending()
                self.handle_update(upd)
                i += 1
                if i == len(akl): i = 0
            except KeyboardInterrupt:
                print("Closing due to Ctrl-C at console")
                self.irc.running = False
                self.running = False
            except:
                print("Incident Watcher encountered an error!")
                print(sys.exc_info()[0])
                print(sys.exc_info()[1])
                traceback.print_tb(sys.exc_info()[-1])
                self.irc.send("\x0314\x1dWarning: Incident Watcher encountered \
an error. See console!\x1d\x0f")
                time.sleep(0.5)
        self.irc.running = False

    def handle_pending(self):
        now = time.time()
        for agency in self.pending:
            depended = set()
##            print("%s has %d events pending" % \
##                  (agency, len(self.pending[agency])))
            for e in self.pending[agency]:
                incid, ts, dm = e
                if now < ts: continue
                depended.add(e)
                active = self.pp_agencies[agency].get_active()
                if not active:
##                    print("Agency no longer has any active incidents.")
                    continue
                # locate this incident in the current incidents list
                found = False
                for inc in active:
                    if inc.id == incid:
                        found = True
                        break
                if not found:
##                    print("Pending incident is no longer active.")
                    continue # incident cleared within 'wait' seconds
                self.incidents[inc.agency.id].add(inc.id)
                if not dm:
##                    print("Asked to not display this incident.")
                    continue
                self.new_inc(inc)
            for e in depended:
                self.pending[agency].remove(e)

    def handle_update(self, upd, display=True):
        now = time.time()
        if not upd: return
        for inc in filter(self.printable, upd.new_incs):
            self.add_inc(inc, display=display)
        for inc in upd.rem_incs:
            if inc.id not in self.incidents[upd.agency.id]: return
            self.incidents[upd.agency.id].discard(inc.id)
            if not display: return
            self.cleared_inc(inc)
        for (inc, delta) in filter(None, upd.chg_incs):
            if "call_type" in delta.changes:
                if not self.printable(inc): continue
                if self.working_inc(inc): self.upd_inc(inc)
                elif self.pending_inc: pass # it's passed by reference anyways
                else: self.add_inc(inc, display=display)
                

    def new_inc(self, inc):
        if len(inc.units) == 1: units = "1 unit assigned"
        else: units = "%d units assigned" % len(inc.units)
        print("NEW INCIDENT in %s: %s at %s (%s)" % \
              (inc.agency.name, inc.ct(), inc.loc, units))
        self.irc.send("\x0304\x02NEW INCIDENT\x02\x0f in %s (%s): %s at \
%s (%s)" % (inc.agency.name, inc.agency.id, inc.ct(), inc.loc, units))

    def cleared_inc(self, inc):
        if len(inc.units) == 1: units = "1 unit assigned"
        else: units = "%d units assigned" % len(inc.units)
        print("INCIDENT CLEARED by %s (%s): %s at %s (%s)"%\
              (inc.agency.name, inc.agency.id, inc.ct(), inc.loc, units))
        self.irc.send("\x0312\x02INCIDENT CLEARED\x02\x0f by %s: \
%s at %s (%s)" % (inc.agency.name, inc.ct(), inc.loc, units))
        
    def upd_inc(self, inc):
        if len(inc.units) == 1: units = "1 unit assigned"
        else: units = "%d units assigned" % len(inc.units)
        print("INCIDENT UPDATED by %s (%s): %s at %s (%s)" % \
              (inc.agency.name, inc.agency.id, inc.ct(), inc.loc, units))
        self.irc.send("\x0307\x02INCIDENT UPDATED\x02\x0f by %s: \
%s at %s (%s)" % (inc.agency.name, inc.ct(), inc.loc, units))

    def working_inc(self, inc):
        return inc.id in self.incidents[inc.agency.id]

    def pending_inc(self, inc):
        return inc.id in map(lambda q:q[0], self.pending[inc.agency.id])

    def add_inc(self, inc, display=True):
        self.pending[inc.agency.id].add((inc.id,
                                         time.time()+self.wait,
                                         display))
    def printable(self, inc):
        return relevant2(inc)


def oo_main():
    agencies = [PulsePoint("56020", "VCFD"),
                PulsePoint("LAFDC", "LAFD Central"),
                PulsePoint("LAFDN", "LAFD North"),
                PulsePoint("LAFDS", "LAFD South"),
                PulsePoint("LAFDW", "LAFD West")]
    for agency in agencies:
        agency.update()
        [inc.test() for inc in filter(relevant2, agency.list_active())]
        time.sleep(0.5)
        print()
    i = 0
    try:
        while True:
            [time.sleep(1./len(agencies)) for j in range(30)]
##            print("Updating...\n")
            upd = agencies[i].update()
            form_agency_update(upd)
            i += 1
            if i == len(agencies): i = 0
    except KeyboardInterrupt:
        print("Exiting")

                         
if __name__ == "__main__": #oo_main()
    i = IncidentWatcher()
    i.loop()


# 2020/06/10
##Traceback (most recent call last):
##  File "pulsepoint.py", line 557, in <module>
##    if __name__ == "__main__": oo_main()
##  File "pulsepoint.py", line 548, in oo_main
##    form_agency_update(upd)
##  File "pulsepoint.py", line 514, in form_agency_update
##    print("%d %s unit%s removed from %s @ %s:" % \
##TypeError: %d format: a number is required, not str
