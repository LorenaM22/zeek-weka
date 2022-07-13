@load base/protocols/conn
@load base/utils/time
@load base/protocols/ssl
@load base/protocols/dns
@load base/files/x509

module Conn;

export {
		function set_conn_log_data_hack(c: connection)
			{
				Conn::set_conn(c, T);
			}
}

module OpenConnection;

const ALERT_INTERVAL = 1min;

export {
	redef enum Log::ID += { LOG };
	

	type Info: record{
		ts:	string &log;
		uid:	string &log;
		orig_address:	addr &log;
		orig_port:	port &log;
		resp_address:	addr &log;
		resp_port:	port &log;
		protocol:	string &log;
		service:	string &log ;
		duration:	interval &log;
		orig_bytes:	string &log;
		resp_bytes:string &log;
		conn_state:	string &log;
		local_orig:	bool &log;
		local_resp: bool &log;
		missed_bytes: count &log;
		history:	string &log;
		orig_packets:	string &log;
		orig_ip_bytes:	count &log;
		resp_packets:	string &log;
		resp_ip_bytes:	count &log;
		tunnel_parents:	set[string] &log;
		intervals_orig: string &log;
		intervals_resp: string &log;
	
	};
	
	global timing_orig: table[conn_id] of vector of string= table() &create_expire=1 day;
	global timing_resp: table[conn_id] of vector of string= table() &create_expire=1 day;
	global orig_bytes: table[conn_id] of vector of string= table() &create_expire=1 day;
	global resp_bytes: table[conn_id] of vector of string= table() &create_expire=1 day;
	global orig_packets: table[conn_id] of vector of string= table() &create_expire=1 day;
	global resp_packets: table[conn_id] of vector of string= table() &create_expire=1 day;

}
redef record connection += {
        ## Offset of the currently watched connection duration by the long-connections script.
        long_conn_offset: count &default=0;
};

event zeek_init() 
        {
        Log::create_stream(LOG, [$columns=Info, $path="per_packet_dif"]);
        }

function information(c: connection): OpenConnection::Info 
	{

		local rec: OpenConnection::Info ;
			
		rec$ts=strftime("%Y-%m-%d %H:%M:%S",c$conn$ts);
		rec$uid=c$conn$uid;
		rec$orig_address=c$conn$id$orig_h;
		rec$orig_port=c$conn$id$orig_p;
		rec$resp_address=c$conn$id$resp_h;
		rec$resp_port=c$conn$id$resp_p;
		rec$protocol=cat(c$conn$proto);
		if (c$conn?$service){
			rec$service=c$conn$service;
		}
		if (c$conn?$duration){
			rec$duration=c$conn$duration;
		}
		
		if (c$conn$id !in timing_orig ){
			if(c$conn?$duration){
				rec$intervals_orig=cat(c$conn$duration);
			}
		}
		if (c$conn$id in timing_orig){
				rec$intervals_orig=join_string_vec(timing_orig[c$conn$id], "-");
				delete timing_orig[c$conn$id];
		}
		if (c$conn$id !in timing_resp ){
			if(c$conn?$duration){
				rec$intervals_resp=cat(c$conn$duration);
			}
		}
		if (c$conn$id in timing_resp){
				rec$intervals_resp=join_string_vec(timing_resp[c$conn$id], "-");
				delete timing_resp[c$conn$id];
		}
		
		if (c$conn$id !in orig_bytes){
			if(c$conn?$orig_bytes){
				rec$orig_bytes=cat(c$conn$orig_bytes);
			}
		}
		if (c$conn$id !in resp_bytes ){
			if(c$conn?$resp_bytes){
				rec$resp_bytes=cat(c$conn$resp_bytes);
			}
		}
		if (c$conn$id in orig_bytes){
				rec$orig_bytes=join_string_vec(orig_bytes[c$conn$id], "-");
				delete orig_bytes[c$conn$id];
		}
		if (c$conn$id in resp_bytes){
			rec$resp_bytes=join_string_vec(resp_bytes[c$conn$id], "-");
				delete resp_bytes[c$conn$id];
			
		}
		if (c$conn?$conn_state){
			rec$conn_state=c$conn$conn_state;
		}
		if (c$conn?$local_orig){
			rec$local_orig=c$conn$local_orig;
		}
		if (c$conn?$local_resp){
			rec$local_resp=c$conn$local_resp;
		}
		if (c$conn?$missed_bytes){
			rec$missed_bytes=c$conn$missed_bytes;
		}
		if (c$conn?$history){
			rec$history=c$conn$history;
		}
		if (c$conn$id !in orig_packets ){
			if(c$conn?$orig_pkts){
				rec$orig_packets=cat(c$conn$orig_pkts);
			}
		}
		if (c$conn$id in orig_packets){
			rec$orig_packets=join_string_vec(orig_packets[c$conn$id], "-");
			delete orig_packets[c$conn$id];
		}
		if (c$conn?$orig_ip_bytes){
			rec$orig_ip_bytes=c$conn$orig_ip_bytes;
		}
		if (c$conn$id !in resp_packets ){
			if(c$conn?$resp_pkts){
				rec$resp_packets=cat(c$conn$resp_pkts);
			}
		}
		if (c$conn$id in resp_packets ){
			rec$resp_packets=join_string_vec(resp_packets[c$conn$id], "-");
			delete resp_packets[c$conn$id];
		}
		if (c$conn?$resp_ip_bytes){
			rec$resp_ip_bytes=c$conn$resp_ip_bytes;
		}
		if (c$conn?$tunnel_parents){
			rec$tunnel_parents=c$conn$tunnel_parents;
		}
		
		
		return rec;
	}

function keep(c: connection)
	{
		
		if (c$conn$id in orig_packets){
			if(c$conn?$orig_pkts){
				if (c$conn$orig_pkts !in 	orig_packets[c$conn$id]){
					orig_packets[c$conn$id]+=cat(c$conn$orig_pkts);
					if (c$conn$id in orig_bytes){
						if(c$conn?$orig_bytes){
								orig_bytes[c$conn$id]+=cat(c$conn$orig_bytes);
								timing_orig[c$conn$id]+=cat(c$conn$duration);
						}
						else{
							orig_bytes[c$conn$id]+=cat(0);
							timing_orig[c$conn$id]+=cat(0.0secs);						
						}
					}
					else{
						if(c$conn?$orig_bytes){
							orig_bytes[c$conn$id]=[cat(c$conn$orig_bytes)];
							timing_orig[c$conn$id]=[cat(c$conn$duration)];
						}
						else{
							orig_bytes[c$conn$id]=[cat(0)];
							timing_orig[c$conn$id]=[cat(0.0secs)];						
						}
					}
				}
			}
		}
		else{
			if(c$conn?$orig_pkts){
				orig_packets[c$conn$id]=[cat(c$conn$orig_pkts)];
				if (c$conn$id in orig_bytes){
					if(c$conn?$orig_bytes){
						orig_bytes[c$conn$id]+=cat(c$conn$orig_bytes);
						timing_orig[c$conn$id]+=cat(c$conn$duration);
					}
					else{
						orig_bytes[c$conn$id]+=cat(0);
						timing_orig[c$conn$id]+=cat(0.0secs);
					}
				}
				else{
					if(c$conn?$orig_bytes){
						orig_bytes[c$conn$id]=[cat(c$conn$orig_bytes)];
						timing_orig[c$conn$id]=[cat(c$conn$duration)];
					}
					else{
						orig_bytes[c$conn$id]=[cat(0)];
						timing_orig[c$conn$id]=[cat(0.0secs)];
					}
				}
			}
		}
		
		if (c$conn$id in resp_packets ){
			if(c$conn?$resp_pkts){
				if (c$conn$resp_pkts !in 	resp_packets[c$conn$id]){
					resp_packets[c$conn$id]+=cat(c$conn$resp_pkts);
					if (c$conn$id in resp_bytes){
						if(c$conn?$resp_bytes){
								resp_bytes[c$conn$id]+=cat(c$conn$resp_bytes);
								timing_resp[c$conn$id]+=cat(c$conn$duration);
						}
						else{
								resp_bytes[c$conn$id]+=cat(0);
								timing_resp[c$conn$id]+=cat(0.0secs);
						}
					}
					else{
						if(c$conn?$resp_bytes){
							resp_bytes[c$conn$id]=[cat(c$conn$resp_bytes)];
							timing_resp[c$conn$id]=[cat(c$conn$duration)];
						}
						else{
							resp_bytes[c$conn$id]=[cat(0)];
							timing_resp[c$conn$id]=[cat(0.0secs)];
						}
					}
				}
			}
		}
		else{
			if(c$conn?$resp_pkts){
				resp_packets[c$conn$id]=[cat(c$conn$resp_pkts)];
				if (c$conn$id in resp_bytes){
					if(c$conn?$resp_bytes){
							resp_bytes[c$conn$id]+=cat(c$conn$resp_bytes);
							timing_resp[c$conn$id]+=cat(c$conn$duration);
					}
					else{
							resp_bytes[c$conn$id]+=cat(0);
							timing_resp[c$conn$id]+=cat(0.0secs);
					}
				}
				else{
					if(c$conn?$resp_bytes){
						resp_bytes[c$conn$id]=[cat(c$conn$resp_bytes)];
						timing_resp[c$conn$id]=[cat(c$conn$duration)];
					}
					else{
						resp_bytes[c$conn$id]=[cat(0)];
						timing_resp[c$conn$id]=[cat(0.0secs)];
					}
				}
			}
		}	
	}




event new_packet(c: connection, p: pkt_hdr){
		Conn::set_conn_log_data_hack(c);
		keep(c);
}

event connection_state_remove(c: connection)
        {
				
		#print "end log conexion", c$id, c$duration;
		Conn::set_conn_log_data_hack(c);
                Log::write(OpenConnection::LOG, information(c));
	}
