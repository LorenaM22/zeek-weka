## Examples
Extraido del repositorio dgunter/ParseZeekLogs, al que se le ha realizado una modificación en el fichero examples/zeek_to_csv.py para incluir nuestros campos de interes obtenidos por zeek. Dentro de examples se encuentra ya un ejemplo realizado: el conn.log está parseado en out.csv con formato csv.

Primero descargamos el repositorio en un directorio conocido por ejemplo en /root, con el siguiente comando: git clone https://github.com/LorenaM22/zeek-weka.git
Así nos aparecerá en él un nuevo directorio llamado zeek-weka.

Para realizar el cambio de log a csv, el fichero de zeek conn.log debe crearse con su formato por defecto y no con formato json. Por lo tanto, se deberá analizar los ficheros .pcap con el siguiente comando:  /opt/zeek/bin/zeek -r test.pcap -C
Y una vez obtenido el fichero conn.log nos situamos en su directorio y ejecutamos el siguiente comando: python3 /root/zeek-weka/examples/zeek_to_csv.py conn.log
Una vez ejecutado el comando se nos habrá creado en ese mismo directorio el fichero out.csv que contiene los siguientes campos de zeek:
"ts", "uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"

(Si te aparece algún error de que falta algún modulo de elasticsearch simplemente ejecuta pip install elasticsearch para descargar el módulo y vuelve a intentarlo)

### Campos de interes para Weka (información extraída de https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info):
  * ts: tiempo del primer paquete -> parsear a UTC
  * duration: cuanto ha durado la conexión (campo de tipo intervalo, sus unidades son segundos)
  * orig_bytes: número de bytes de origen a destino
  * resp_bytes: número de bytes de destino a origen
  * conn_state (Posibles valores):
    * S0: Connection attempt seen, no reply.
    * S1: Connection established, not terminated.
    * SF: Normal establishment and termination. Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there will not be any byte counts in the summary, while for SF there will be.
    * REJ: Connection attempt rejected.
    * S2: Connection established and close attempt by originator seen (but no reply from responder).
    * S3: Connection established and close attempt by responder seen (but no reply from originator).
    * RSTO: Connection established, originator aborted (sent a RST).
    * RSTR: Responder sent a RST.
    * RSTOS0: Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
    * RSTRH: Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
    * SH: Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open).
    * SHR: Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
    * OTH: No SYN seen, just midstream traffic (one example of this is a “partial connection” that was not later closed).
  * missed_bytes: cantidad de bytes perdidos en los gaps (representa un poco los paquetes perdidos en la conexión)
  * history: es una ristra de letras que representa la historia del estado de la conexión (en si podemos pasearlo para tener los flags empleados)
    * s: a SYN without the ACk bit set
    * h: A SYN+ACK (handshake)
    * a: a pure ACK
    * d: packet with payload (“data”)
    * f: packet with FIN bit set
    * r: packet with RST bit set
    * c: packet with a bad checksum (applies to UDP too)
    * g: a content gap
    * t: packet with retransmitted payload
    * w: packet with a zero window advertisement
    * i: inconsistent packet (e.g. FIN+RST bits set)
    * q: multi-flag packet (SYN+FIN or SYN+RST bits set)
    * ^: connection direction was flipped by Zeek’s heuristic    
    If the event comes from the originator, the letter is in upper-case; if it comes from the responder, it’s in lower-case. 
  * orig_pkts: paquetes de origen a destino
  * resp_pkts: paquetes de destino a origen
  
Si en vez de ejecutar el script zeek_to_csv.py se ejecuta zeek_to_csv_UTC.py, se tendrá un campo más al principio de cada fila que corresponde al campo ts en formato UTC. Pero se vuelve un programa muy lento.

## JSON
En la carpeta json encontramos el script necesario para parsear ficheros log que contienen datos en formato json a un fichero csv. Para que ejecutar simplemente es necesario el siguiente comando: python3 json_to_csv.py conn.log
Y si en su lugar ejecutamos json_to_csv_UTC.py aparecerá el campo ts en formato UTC en el fichero csv.

## Zeek Script
Dentro de la carpeta zeek script encontramos los scripts personalizados de zeek:
  * first_minute.zeek nos aporta información del primer minuto de las conexiones o si las conexiones tienen una duración inferior de su totalidad -> archivo fist_minute.log
  * alert_interval.zeek se dedica a analizar "cada minuto" la conexión y cuando esta finaliza aporta todos sus datos. Lo relevante de este script es que los campos orig_bytes, resp_bytes, orig_pkts y resp_pkts son vectores que nos indican cuantos bytes han sido recibidos hasta el tiempo indicado en el vector intervals. Por ejemplo si orig_bytes=[10,20] e intervals=[60.0, 120.3], nos indica que en los primeros 60 segundos de la conexión se han enviado 10 bytes y en los primeros 120.3 segundos se han enviado 20. Es decir, que en el segundo minuto de la conexión se han recibido 10 bytes -> archivo interval.log  
  * per_packet.zeek analiza cada uno de los paquetes de la conexión y cuando esta finaliza aporta todos los datos. Lo relevante de este script vuelven a ser los campos  orig_bytes, resp_bytes, orig_pkts y resp_pkts que son vectores que incluyen un nuevo valor cada vez que se recibe un paquete en cada uno de los sentidos. Si el destino envia un paquete resp_bytes y resp_pkts incluirán un nuevo elemento. Además, el vector intervals especifica el instante de tiempo de la conexión en la que se intercambian paquetes (intervals=[0, 20, 20, 30] se han intercambiado un paquete en el inicio de la conexión, 2 paquetes en el segundo 20 de la conexión y 1 paquete en el segundo 30 de la conexión) -> archivo per_packet.log  
  * per_packet_dif.zeek realiza lo mismo que el script per_packet.zeek pero este tiene dos vectorres, intervals_orig e intervals_resp para saber el tiempo de separación entre paquetes en cada uno de los sentidos -> archivo per_packet_dif.log
  * per_packet_enrich.zeek realiza lo mismo que el script per_packet_dif.zeek pero enriquece la información con datos sobre los nombres DNS, la conexión SSL y los certificados x509 usados -> archivo per_packet_enrich.log 
 (Los ficheros log de salida aportan el campo ts en formato UTC)
