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

const ALERT_INTERVAL = 5secs;

export {
	redef enum Log::ID += { LOG };
	
	type Certs: record{
		certificate_version: count &log;
		certificate_serial:	string &log;
		certificate_subject:	string &log;
		certificate_issuer:	string &log;
		certificate_cn:	string &log;
		certificate_not_valid_before: time &log;
		certificate_not_valid_after: time &log;
		certificate_key_alg: string &log;
		certificate_sig_alg:	string &log;
		certificate_key_type:	string &log;
		certificate_key_len:	count &log;
		certificate_exponent:	string &log;
		certificate_curve:	string &log;
		san_dns: vector of string &log;
		san_uri: vector of string &log;
		san_email:vector of string &log;
		san_ip: vector of addr &log;
		basic_constraints_ca: bool &log;
		basic_constrainst_path_len: count &log;
	};
	
	type Info: record{
		destinationAddress: addr &log;
		sourceAddress: addr &log;
		destinationPort: port &log;
		sourcePort: port &log;
		startTime: time &log;
		deviceCustomString19:	string &log;
		deviceCustomString19Label: string &default= "protocol" &log;
		
		sourceDnsDomain:	vector of string &log ;
		destinationDnsDomain:	vector of string &log ;
		deviceCustomString1: string &log;
		deviceCustomString1Label: string &default="server dns" &log;
		
		sourceHostName:	vector of string &log ;
		destinationHostName:	vector of string &log ;	
		
		deviceCustomString2:	string &log ;
		deviceCustomString2Label: string &default= "next protocol the server choses using the applitcation layer next protocol extension"   &log;
		deviceCustomString3:	string &log ;
		deviceCustomString3Label: string &default= "last alert that was seen during the connection"   &log;
		deviceCustomString4:	string &log ;
		deviceCustomString4Label: string &default="ssl/tls cipher suite that the server chose" &log;
		deviceCustomString5:	string &log ;
		deviceCustomString5Label: string &default= "elliptic curve the server chose when using ecdh/ecdhe"  &log;
		deviceCustomString6:	string &log ;
		deviceCustomString6Label: string &default= "ssl certificate version"  &log;
		deviceCustomBool1:	bool &log ;
		deviceCustomBool1Label: string &default=  "indicate if the ssl session has been established successfully" &log;
		deviceCustomBool2:	bool &log ;
		deviceCustomBool2Label: string &default= "indicate if the session was resumed reusing the key material exchanged in an earlier connection" &log;
		
		deviceCustomNumber1:	string &log;
		deviceCustomNumber1Label: string &default= "rsa-certificate exponent"    &log;
		deviceCustomNumber2:	count &log;
		deviceCustomNumber2Label: string &default= "key length in bits"      &log;
		deviceCustomNumber3: count &log;
		deviceCustomNumber3Label : string &default="version number" &log;
		deviceCustomNumber4: count &log;
		deviceCustomNumber4Label: string &default="basic constraints length"    &log;		
		deviceCustomDate1: time &log;
		deviceCustomDate1Label: string &default="timestamp after when certificate is not valid"  &log;
		deviceCustomDate2: time &log;
		deviceCustomDate2Label: string &default="timestamp before when certificate is not valid"  &log;
		deviceCustomString7:	string &log;
		deviceCustomString7Label: string &default="certificate cn"   &log;	
		deviceCustomString8:	string &log;
		deviceCustomString8Label: string &default="ec-certificate curve"     &log;
		deviceCustomString9:	string &log;
		deviceCustomString9Label: string &default="certificate issuer"   &log;
		deviceCustomString10:	string &log;
		deviceCustomString10Label: string &default="key type"     &log;
		deviceCustomString11:	string &log;
		deviceCustomString11Label: string &default="serial number" &log;
		deviceCustomString12:	string &log;
		deviceCustomString12Label: string &default="name of the signature algorithm"     &log;
		deviceCustomString13:	string &log;
		deviceCustomString13Label: string &default="subject"  &log;
		deviceCustomString14: vector of string &log;
		deviceCustomString14Label: string &default="list of DNS entires in SAN"     &log;
		deviceCustomString15: vector of string &log;
		deviceCustomString15Label: string &default="list of URI entires in SAN"    &log;
		deviceCustomString16:vector of string &log;
		deviceCustomString16Label: string &default="list of emails entires in SAN"    &log;
		deviceCustomString17: vector of addr &log;
		deviceCustomString17Label: string &default="list of IP entires in SAN"    &log;
		deviceCustomString18: string &log;
		deviceCustomString18Label: string &default="name of the key algorithm"    &log;	
		deviceCustomBool3: bool &log;
		deviceCustomBool3Label: string &default="basic constraints extension of certificate"     &log;
		};
		
	global dns: table [addr] of vector of string= table() &create_expire=1 day;
	
	global dns_server:set[addr] &create_expire=1 day; 
	
	
	global cert509: table[conn_id] of Certs=table() &create_expire=1 day;

	global ssl: table [addr] of vector of string= table() &create_expire=1 day;
	
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
	
	rec$destinationAddress=c$id$resp_h;
	rec$sourceAddress=c$id$orig_h;
	rec$destinationPort=c$id$resp_p;
	rec$sourcePort=c$id$orig_p;
	rec$startTime=c$start_time;
	
	rec$deviceCustomString19=cat(c$conn$proto);
		
		
		if(c?$ssl){
			if (c$ssl?$version){
				rec$deviceCustomString6=c$ssl$version;
			}
			if (c$ssl?$cipher){
				rec$deviceCustomString4=c$ssl$cipher;
				}
			if (c$ssl?$curve){
				rec$deviceCustomString5=c$ssl$curve;
			}
			if (c$ssl?$resumed){
					rec$deviceCustomBool2=c$ssl$resumed;
			}
			if (c$ssl?$last_alert){
					rec$deviceCustomString3=c$ssl$last_alert;
			}
			if (c$ssl?$next_protocol){
					rec$deviceCustomString2=c$ssl$next_protocol;
			}
			if (c$ssl?$established){
					rec$deviceCustomBool1=c$ssl$established;
			}
		}
		
		if (c$conn$id$orig_h in dns){
			rec$sourceDnsDomain=dns[c$conn$id$orig_h];
		}
		if (c$conn$id$resp_h in dns){
			rec$destinationDnsDomain=dns[c$conn$id$resp_h];
		}
		
		if (c$conn$id$orig_h in dns_server){
			rec$deviceCustomString1="KNOWN_ORIG_DNS";
		}
		if (c$conn$id$resp_h in dns_server){
			rec$deviceCustomString1="KNOWN_RESP_DNS";
		}
		
		
		if (c$conn$id$orig_h in ssl){
			rec$sourceHostName=ssl[c$conn$id$orig_h];
		}
		if (c$conn$id$resp_h in ssl){
			rec$destinationHostName=ssl[c$conn$id$resp_h];
		}
		
		if ([c$conn$id] in cert509){
			
			rec$deviceCustomNumber1=cert509[c$conn$id]$certificate_exponent;
			rec$deviceCustomNumber2=cert509[c$conn$id]$certificate_key_len;
			rec$deviceCustomNumber3=cert509[c$conn$id]$certificate_version;
			if(cert509[c$conn$id]?$basic_constrainst_path_len){
				rec$deviceCustomNumber4=cert509[c$conn$id]$basic_constrainst_path_len;
			}
			rec$deviceCustomDate1=cert509[c$conn$id]$certificate_not_valid_after;
			rec$deviceCustomDate2=cert509[c$conn$id]$certificate_not_valid_before;
			rec$deviceCustomString7=cert509[c$conn$id]$certificate_cn;
			if(cert509[c$conn$id]?$certificate_curve){
				rec$deviceCustomString8=cert509[c$conn$id]$certificate_curve;
			}
			rec$deviceCustomString9=cert509[c$conn$id]$certificate_issuer;
			rec$deviceCustomString10=cert509[c$conn$id]$certificate_key_type;
			rec$deviceCustomString11=cert509[c$conn$id]$certificate_serial;
			rec$deviceCustomString12=cert509[c$conn$id]$certificate_sig_alg;
			rec$deviceCustomString13=cert509[c$conn$id]$certificate_subject;
			if(cert509[c$conn$id]?$san_dns){
				rec$deviceCustomString14=cert509[c$conn$id]$san_dns;
			}
			if(cert509[c$conn$id]?$san_uri){
				rec$deviceCustomString15=cert509[c$conn$id]$san_uri;
			}
			if(cert509[c$conn$id]?$san_email){
				rec$deviceCustomString16=cert509[c$conn$id]$san_email;
			}
			if(cert509[c$conn$id]?$san_ip){
				rec$deviceCustomString17=cert509[c$conn$id]$san_ip;
			}
			rec$deviceCustomString18=cert509[c$conn$id]$certificate_key_alg;
			
			if(cert509[c$conn$id]?$basic_constraints_ca){
				rec$deviceCustomBool3=cert509[c$conn$id]$basic_constraints_ca;
			}
			delete cert509[c$conn$id];
		}
	
	return rec;
	}



event ssl_established (c: connection){
	if (c$ssl?$server_name){
	
		local it_is=0;
	
		if (c$ssl$id$resp_h !in ssl){
			ssl[c$ssl$id$resp_h]=[c$ssl$server_name];
		}
		else{
			for (name in ssl[c$ssl$id$resp_h]){ 
				if (ssl[c$ssl$id$resp_h][name]==c$ssl$server_name){
					it_is=1;
				}
			}
			if(it_is!=1){
				ssl[c$ssl$id$resp_h]+=c$ssl$server_name;
			}
		}
	
		#ssl[c$ssl$id$resp_h]=c$ssl$server_name;
	}
	else{
		if (c$ssl$id$resp_h !in ssl){
			ssl[c$ssl$id$resp_h]=["SSL server not known name"];
		}
	}
	
}
function long_callback(c: connection, cnt: count): interval
        {

			if ( c$duration >= ALERT_INTERVAL )
				{
					#print  "connection writted", c$id, c$duration;
					Conn::set_conn_log_data_hack(c);
			                Log::write(Enrich_Conn::LOG, information(c));
						return -1sec;
				}
			else
				{
					#print  "connection not writted", c$id, c$duration;
						return ALERT_INTERVAL - c$duration;
				}
		
        }



event dns_A_reply (c: connection, msg: dns_msg, ans: dns_answer, a: addr){
    
	local it_is=0;
	
	if (a !in dns){#si en la tabla dns no hay un linea con índice a
		dns[a]=[ans$query];
	}
	else{#si en la tabla dns hay una línea con indice a
		for (name in dns[a]){ #recorro la linea comprobando si alguno de los valores contenidos corresponde con el nombre seleccionado
			if (dns[a][name]==ans$query){
				it_is=1;#la linea tiene el nombre resuelto almacenado
			}
		}
		if(it_is!=1){#la linea no tiene el nombre resuelto almacenado
			dns[a]+=ans$query;
		}
	}
	
	add dns_server[c$id$resp_h];#almaceno en un vector los servidores dns (IP) de los que recibo respuesta
	#las ips que se encuentren en este vector luego nos permitiran decir que el servidor es conocido
}

event new_connection(c: connection)
        {
                ConnPolling::watch(c, long_callback, 1, ALERT_INTERVAL);
        }

event connection_state_remove(c: connection)
	{
		if ( c$duration < ALERT_INTERVAL )
				{
					#print  "connection writted", c$id, c$duration;
					Conn::set_conn_log_data_hack(c);
			                Log::write(Enrich_Conn::LOG, information(c));
				}
	}



