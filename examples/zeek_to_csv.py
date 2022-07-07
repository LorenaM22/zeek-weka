from parsezeeklogs import ParseZeekLogs
import sys 

with open('out.csv',"w") as outfile:
    for log_record in ParseZeekLogs(sys.argv[1], output_format="csv", safe_headers=False, fields=["ts", "uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]):
        if log_record is not None:
            outfile.write(log_record + "\n")
