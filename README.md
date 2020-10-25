# PulsePoint-Relay
Grab data from PulsePoint and forward incident updates to IRC!

*The core of this project uses some code from [Davnit's pulse.py](https://gist.github.com/Davnit/4d1ccdf6c674ce9172a251679cd0960a) to handle decryption of PulsePoint's data feed. If you think this code is star-worthy, give Davnit's pulse.py a star too since this project would not have been possible without pulse.py.*

This requires [Stickybot](https://github.com/CVSoft/stickybot) for the IRC interface. PulsePoint-Relay was developed around version 1.10, but any version after 1.07 should work without issue. 

The conditions for determining whether an event should be displayed are configured with `relevant2`. Currently (per v1.01), it checks if a fire alarm level is defined and greater than one, or if the incident type is some kind of fire, hazmat incident, or technical rescue. I don't imagine this code handles incidents changed from a non-relevant incident type to a relevant incident type too well, but it does check. 
