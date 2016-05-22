#!/usr/bin/env python

'''
    Author: Bruno Meneuvrier - bruno.meneuvrier@ioxar.fr
    Description: This nagios plugin checks lag members on Ethernet switches
    and controls if they are active. It queries the LAG MIB.

    The plugin was tested on Debian 7 with python 2.7,3 . It requires pysnmp.

    Copyright (C) 2016 - Bruno Meneuvrier - IOxar

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''
__author__ = 'Bruno Meneuvrier - bruno.meneuvrier@ioxar.fr'
__version__= 0.1

from pysnmp.hlapi import *
import sys
from optparse import OptionParser

RET_CODES = {"OK":0,
             "WARNING":1,
             "CRITICAL":2,
             "UNKNOWN":3}

ON_ERROR_RET_CODE = RET_CODES["CRITICAL"]

IFINDEX_OID =  '.1.3.6.1.2.1.2.2.1.1'
IFDESCR_OID = '.1.3.6.1.2.1.2.2.1.2'
IFTYPE_OID = '.1.3.6.1.2.1.2.2.1.3'
DOT3ADAGGPORTSELECTEDAGGID_OID = '.1.2.840.10006.300.43.1.2.1.1.12'
DOT3ADAGGPORTATTACHEDAGGID_OID = '.1.2.840.10006.300.43.1.2.1.1.13'


def parse_options():
    parser = OptionParser()
    parser.add_option("-H",
                      "--host",
                      dest="hostname",
                      type="string",
                      help="Host Name",
                      metavar="HOST"
                      )
    parser.add_option("-c",
                      "--community",
                      dest="community",
                      default="public",
                      type="string",
                      help="SNMP Community Name. [Default:public]"
                      )
    return parser.parse_args()

def validate_parameters(options, args):
    if options.hostname == None:
        print ("Error: host name or ip must be supplied.")
        sys.exit(RET_CODES["UNKNOWN"])

def check_lag(options):
    ret_code = RET_CODES["OK"]
    output = ""
    numport = 0
    # Populate list ports with ifIndex and ifDescr
    ports = []
    aggregates = []
    lagmembers = []
    for iferrorIndication, \
        iferrorStatus, \
        iferrorIndex, \
        ifvarBinds in nextCmd(SnmpEngine(),
                            CommunityData(options.community, mpModel=0),
                            UdpTransportTarget((options.hostname, 161)),
                            ContextData(),
                            # IF-MIB::ifIndex
                            ObjectType(ObjectIdentity(IFINDEX_OID)),
                            # IF-MIB::ifDescr
                            ObjectType(ObjectIdentity(IFDESCR_OID)),
                            # IF-MIB::ifType
                            ObjectType(ObjectIdentity(IFTYPE_OID)),
                            lexicographicMode=False):


        if iferrorIndication:
            return RET_CODES["UNKNOWN"], iferrorIndication
            break
        elif iferrorStatus:
            return RET_CODES["UNKNOWN"], iferrorStatus.prettyPrint() + " at " +\
                   iferrorIndex and ifvarBinds[int(iferrorIndex)-1][0] or '?'
            break
        else:
            # We focus on type ethernetCsmacd(6)
            if ifvarBinds[2][1] == 6:
                ports.append([ifvarBinds[0][1],ifvarBinds[1][1]])
            # We focus on type ieee8023adLag(161)
            elif ifvarBinds[2][1] == 161:
                aggregates.append([ifvarBinds[0][1],ifvarBinds[1][1]])

    for errorIndication, \
        errorStatus, \
        errorIndex, \
        varBinds in nextCmd(SnmpEngine(),
                          CommunityData(options.community, mpModel=0),
                          UdpTransportTarget((options.hostname, 161)),
                          ContextData(),
                          # dot3adAggPortSelectedAggID
                          ObjectType(ObjectIdentity(DOT3ADAGGPORTSELECTEDAGGID_OID)),
                          # dot3adAggPortAttachedAggID
                          ObjectType(ObjectIdentity(DOT3ADAGGPORTATTACHEDAGGID_OID)),
                          lexicographicMode=False):



        if errorIndication:
            return RET_CODES["UNKNOWN"], \
                   "UNKNOWN: " + errorIndication
            break
        elif errorStatus:
            return RET_CODES["UNKNOWN"], errorStatus.prettyPrint() + " at " +\
                   errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            break
        else:
            ifidx = int(str(varBinds[0][0]).split('.')[11])
            # LAG idx has to be different from If idx
            # in order to be member of a LAG
            if ifidx != varBinds[0][1]:
                lagmembers.append([ifidx,varBinds[0][1],varBinds[1][1]])
    
    for lagmember in lagmembers:
        numport = numport + 1
        aggregate_name = ''
        port_name =''
        # If Selected and Attached LAG are different we consider
        # this port as Inactive in LAG
        if lagmember[1] != lagmember[2]:
            # Find description for port
            for port in ports:
                if port[0] == lagmember[0]:
                    port_name = port[1]
            # Find description for aggregate
            for aggregate in aggregates:
                if aggregate[0] == lagmember[1]:
                    aggregate_name = aggregate[1]            
                        
            output = output + "Port " + port_name + " is inactive in " + \
                     aggregate_name + ", "
            ret_code = RET_CODES["CRITICAL"]
    if ret_code == RET_CODES["OK"]:
        if numport == 0:
            output = "No lag is defined"
        elif numport == 1:
            output = "OK: 1 port is active in lag"
        else:
            output = "OK: " + str(numport) + " ports are active in lag"
    elif ret_code == RET_CODES["CRITICAL"]:
        output = "CRITICAL: " + output
    return ret_code,output

def main():

    try:
        (options, args) = parse_options()
        validate_parameters(options, args)
        retcode,output = check_lag(options)
        print (output)
        sys.exit(retcode)
    except Exception as e:
        return RET_CODES["UNKNOWN"],"UNKNOWN: Unexpected error\n" + str(e)

if __name__ == '__main__':
    main()
    