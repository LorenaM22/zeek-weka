from parsezeeklogs import ParseZeekLogs
import sys 
import os
from datetime import datetime
import subprocess as sp
with open('out.csv',"w") as outfile:
    for log_record in ParseZeekLogs(sys.argv[1], output_format="csv", safe_headers=False, fields=["ts", "uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]):
        if log_record is not None:
            record=log_record.split(',')
            ts= sp.getoutput('date -d @'+record[0])
            lista=[ts, log_record]
            new=','.join(lista)
            #print(new)
            #new=','.join(lista)
            #print (new)
            outfile.write(new + "\n")
            #print(record[0])
            #print( os.system('date -d @'+record[0]))
