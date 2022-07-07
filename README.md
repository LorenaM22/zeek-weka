Extraido del repositorio dgunter/ParseZeekLogs, al que se le ha realizado una modificación en el fichero Examples/zeek_to_csv.py para incluir nuestros campos de interes
obtenidos por zeek.
Dentro de examples se encuentra ya un ejemplo realizado: el conn.log está parseado en out.csv con formato csv.

Primero descargamos el repositorio en un directorio conocido por ejemplo en /root, con el siguiente comadno: git clone https://github.com/LorenaM22/zeek-weka
Así nos aparecerá en él un nuevo directorio llamado ParseZeekLogs

Para realizar el cambio de log a csv, el fichero de zeek conn.log debe crearse con su formato por defecto y no con formato json. Por lo tanto, se deberá analizar los 
ficheros .pcap con el siguiente comando:  /opt/zeek/bin/zeek -r test.pcap -C
Y una vez obtenido el fichero conn.log nos situamos en su directorio y ejecutamos el siguiente comando: python3 /root/ParseZeekLogs/examples/zeek_to_csv.py conn.log
Una vez ejecutado el comando se nos habrá creado en ese mismo directorio el fichero out.csv que contiene los siguientes campos de zeek:
"ts", "uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", 
"history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"

(Si te aparece algún error de que falta algún modulo de elasticsearch simplemente ejecuta pip install elasticsearch para descargar el módulo y vuelve a intentarlo)

Campos de interes para Weka (información extraída de https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info):
  ts: tiempo del primer paquete -> parsear a UTC
  duration: cuanto ha durado la conexión (campo de tipo intervalo, comprobar que unidades tiene)
  orig_bytes: número de bytes de origen a destino
  resp_bytes: número de bytes de destino a origen
  conn_state (Posibles valores):
    S0: Connection attempt seen, no reply.
    S1: Connection established, not terminated.
    SF: Normal establishment and termination. Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there will not be any 
    byte counts in the summary, while for SF there will be.
    REJ: Connection attempt rejected.
    S2: Connection established and close attempt by originator seen (but no reply from responder).
    S3: Connection established and close attempt by responder seen (but no reply from originator).
    RSTO: Connection established, originator aborted (sent a RST).
    RSTR: Responder sent a RST.
    RSTOS0: Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
    RSTRH: Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
    SH: Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open).
    SHR: Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
    OTH: No SYN seen, just midstream traffic (one example of this is a “partial connection” that was not later closed).
  missed_bytes: cantidad de bytes perdidos en los gaps (representa un poco los paquetes perdidos en la conexión)
  history: es una ristra de letras que representa la historia del estado de la conexión (en si podemos pasearlo para tener los flags empleados)
    s: a SYN without the ACk bit set
    h: A SYN+ACK (handshake)
    a: a pure ACK
    d: packet with payload (“data”)
    f: packet with FIN bit set
    r: packet with RST bit set
    c: packet with a bad checksum (applies to UDP too)
    g: a content gap
    t: packet with retransmitted payload
    w: packet with a zero window advertisement
    i: inconsistent packet (e.g. FIN+RST bits set)
    q: multi-flag packet (SYN+FIN or SYN+RST bits set)
    ^: connection direction was flipped by Zeek’s heuristic
  orig_pkts: paquetes de origen a destino
  resp_pkts: paquetes de destino a origen
