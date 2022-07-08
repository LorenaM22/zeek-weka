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

module Enrich_Conn;

const ALERT_INTERVAL = 1min;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record{
		ts:	time &log;
		uid:	string &log;
		orig_address:	addr &log;
		orig_port:	port &log;
		resp_address:	addr &log;
		resp_port:	port &log;
		protocol:	string &log;
		service:	string &log ;
		duration:	interval &log;
		orig_bytes:	count &log;
		resp_bytes: count &log;
		conn_state:	string &log;
		local_orig:	bool &log;
		local_resp: bool &log;
		missed_bytes: count &log;
		history:	string &log;
		orig_packets:	count &log;
		orig_ip_bytes:	count &log;
		resp_packets:	count &log;
		resp_ip_bytes:	count &log;
		tunnel_parents:	set[string] &log;
	
	};
	
}


redef record connection += {
        ## Offset of the currently watched connection duration by the long-connections script.
        long_conn_offset: count &default=0;
};

event zeek_init() 
        {
        Log::create_stream(LOG, [$columns=Enrich_Conn::Info, $path="enrich_conn"]);
        }

function information(c: connection): Enrich_Conn::Info 
	{

		local rec: Enrich_Conn::Info;
		
		rec$ts=c$conn$ts;
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
		if(c$conn?$orig_bytes){
			rec$orig_bytes=c$conn$orig_bytes;
		}
		if(c$conn?$resp_bytes){
			rec$resp_bytes=c$conn$resp_bytes;
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
		if(c$conn?$orig_pkts){
			rec$orig_packets=c$conn$orig_pkts;
		}
		if (c$conn?$orig_ip_bytes){
			rec$orig_ip_bytes=c$conn$orig_ip_bytes;
		}
		if(c$conn?$resp_pkts){
			rec$resp_packets=c$conn$resp_pkts;
		}		
		if (c$conn?$resp_ip_bytes){
			rec$resp_ip_bytes=c$conn$resp_ip_bytes;
		}
		if (c$conn?$tunnel_parents){
			rec$tunnel_parents=c$conn$tunnel_parents;
		}
	
	return rec;
	}


function long_callback(c: connection, cnt: count): interval
        {

			if ( c$duration >= ALERT_INTERVAL )
				{
					#print  "connection writted", c$id, c$duration;
					Conn::set_conn_log_data_hack(c);
			                Log::write(Enrich_Conn::LOG, information(c));
							add finish[c$id];
						return -1sec;
				}
			else
				{
					#print  "connection not writted", c$id, c$duration;
						return ALERT_INTERVAL - c$duration;
				}
		
        }

event new_connection(c: connection)
        {
                ConnPolling::watch(c, long_callback, 1, ALERT_INTERVAL);
        }

event connection_state_remove(c: connection)
	{
		if (c$id in finish){
			delete finish[c$id];
		}
		else{
			#print "end log conexion", c$id, c$duration;
			Conn::set_conn_log_data_hack(c);
			Log::write(Enrich_Conn::LOG, information(c));
		}
	}



