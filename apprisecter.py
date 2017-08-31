

#!/usr/bin/env python

#######
# based on a script by Mike Albano
# adapted for this use by Bruce McMurdo
########

import os, os.path, sys
from pysnmp.entity.rfc3413.oneliner import cmdgen
from datetime import datetime

# Define your snmp RO String
SNMP_RO = 'public'

def snmp_bulkwalk(oid, wlc):
    errorIndication, errorStatus, errorIndex, varBindTable = cmdgen.CommandGenerator().bulkCmd(
      cmdgen.CommunityData(SNMP_RO),
      # IF using SNMPv3 uncomment the following lines, and comment out the above line
      #cmdgen.UsmUserData('v3user', 'usrename-123456789e', 'abcdefabcdefabcdef',
      #authProtocol=cmdgen.usmHMACSHAAuthProtocol,
      #privProtocol=cmdgen.usmAesCfb128Protocol),
      cmdgen.UdpTransportTarget((wlc, 161)),
      0, 25,
      oid,
    )

# Check for errors
    if errorIndication:
      print(errorIndication)
    else:
      if int(errorStatus) != 0:
        print('%s at %s' % (
          errorStatus.prettyPrint(),
          errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
          )
        )

# success
    oid_value = []
    if int(errorStatus) == 0:
      for varBindTableRow in varBindTable:
        #print varBindTableRow
        for name, val in varBindTableRow:
          # the following returns only the OID's we are interested in, and nothing extra
          #print name
          #print(type(name))
          namestr = str(name)
          #print(type(namestr))
          if namestr[:len(oid)] == oid:
            #print "yes"
            oid_value.append((val.prettyPrint(), name.prettyPrint()))
          else:
            print "no"
    # return the list of OID & Values
    return oid_value

# function to call snmp_bulkwalk & create dict of ap names to OID's
def ap_to_oids(controller):
    ap_name = []
    ap_baseradio = []
    ap_wlcname = []
    ap_model = []
    ap_ip = []
    ap_group = []
    ap_ethmac = []
    ap_sec_wlc = []
    ap_ter_wlc = []
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.3.', controller):
      if len(value) == 0:
        value = "Null"
      ap_name.append(value)
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.1.', controller):
      if len(value) == 0:
        value = "Null"
      ap_baseradio.append(value)
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.10.', controller):
      if len(value) == 0:
        value = "Not Configured"
      ap_wlcname.append(value)
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.16.', controller):
      if len(value) == 0:
        value = "Null"
      ap_model.append(value)
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.19.', controller):
      if len(value) == 0:
        value = "Null"
      ap_ip.append(value)
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.30.', controller):
      if len(value) == 0:
        value = "Null"
      ap_group.append(value)
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.33.', controller):
      if len(value) == 0:
        value = "Null"
      ap_ethmac.append(value)
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.23.', controller):
      if len(value) == 0:
        value = "Not Configured"
      ap_sec_wlc.append(value)
    for value, oid in snmp_bulkwalk('1.3.6.1.4.1.14179.2.2.1.1.24.', controller):
      if len(value) == 0:
        value = "Not Configured"
      ap_ter_wlc.append(value)
    allvalues = zip(ap_name, ap_baseradio, ap_wlcname, ap_model, ap_ip, ap_group, ap_ethmac, ap_sec_wlc, ap_ter_wlc)
    for item in allvalues:
      yield str(item[0]), str(item[4]), str(item[2]), str(item[7]), str(item[8]), str(item[1]), str(item[6]), str(item[5]), str(item[3])


###################################################################################

wlc_list = ['10.0.0.2']

class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open("/tmp/wlc_aps3", "w")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)  

    def flush(self):
        #this flush method is needed for python 3 compatibility.
        #this handles the flush command by doing nothing.
        #you might want to specify some extra behavior here.
        pass    

sys.stdout = Logger()


print('+----------------------------------------------------------------------------------------------------')
print('| AP configuration')
print('+-----------------+-------------------+-------------------+-------------------+--------------------')
print('| AP Name         | AP IP             | AP Primary WLC    | AP Secondary WLC  | AP Tertiary AP     ')
print('+-----------------+-------------------+-------------------+-------------------|--------------------')

for wlc in wlc_list:
    for a, b, c, d, e, f, g, h, i in ap_to_oids(wlc):
      print('| ' + format(a, '<15') + ' | ' + \
      format(b, '<17') + ' | ' + \
      format(c, '<17' ) + ' | ' + \
      format(d, '<17' ) + ' | ' + \
      e)

print('+-----------------+-------------------+-------------------+-------------------+--------------------')
print('| Report generated (UTC): ' + str(datetime.now()))
print('+----------------------------------------------------------------------------------------------------')