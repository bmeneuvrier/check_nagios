# check_nagios
## check_lag

This nagios plugin checks lag members on Ethernet switches and controls if they are active.
It queries the LAG MIB (.1.2.840.10006.300.43).
For each ethernet port, it compares Lag Port Actor Oper Key (.1.2.840.10006.300.43.1.2.1.1.5) and interface idx (.1.3.6.1.2.1.2.2.1.1).
If they are the same or if Port Actor Oper Key is zero, it means this interface is not part of an aggregate.
It they are different, it compares selected Lag Port Actor Oper Key (.1.2.840.10006.300.43.1.2.1.1.5) and attached LAG idx (.1.2.840.10006.300.43.1.2.1.1.13).
If they are different, we consider this port as Inactive in LAG.

This plugin works with lacp or static aggregate. For now, it supports only snmp v2. I plan to support v1 and v3 in the future.

It has been tested with following hardware:
- Cisco SG300
- Dell N2048
- Dell N4064

### Usage:

./check_lag.py -h
```
Usage: check_lag.py [options]

Options:
  -h, --help            show this help message and exit
  -H HOST, --host=HOST  Host Name
  -c COMMUNITY, --community=COMMUNITY
                        SNMP Community Name. [Default:public]
```
### Example:

./check_lag.py -H net001.ioxar.fr
```
OK: 1 port is active in lag
```
./check_lag.py -H net002.ioxar.fr
```
No lag is defined
```
./check_lag.py -H net007.ioxar.fr
```
CRITICAL: Port gigabitethernet2 is inactive in Po1
Port gigabitethernet6 is inactive in Po2
```
