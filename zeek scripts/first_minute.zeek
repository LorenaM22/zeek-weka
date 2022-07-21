#Empleado en el script de github necesario, porque si lo quitas aparecen problemas cuando se escriben las conexiones en los archivos de logs

#Se escribe la información de las conexiones cada minuto que estén activas y cuando se eliminan de la memoria (de esta forma no se perderán conexiones cuya duración sea menor que un minuto)

@load base/protocols/conn
@load base/utils/time

module Conn;

export {
function set_conn_log_data_hack(c: connection)
        {
        Conn::set_conn(c, T);
        }
}

module First_Min;

const ALERT_INTERVAL = 1min;
export {
        redef enum Log::ID += { LOG };

}
redef record connection += {
        ## Offset of the currently watched connection duration by the long-connections script.
        long_conn_offset: count &default=0;
};

event zeek_init() 
        {
        Log::create_stream(LOG, [$columns=Conn::Info, $path="first_minute"]);
        }


function long_callback(c: connection, cnt: count): interval
        {
#El formato de la función long_callbakc viene predefinido para ser usado: tiene como argumentos la conexión a monitorizar, el contador que indica cuantas veces se ha ejecutado para esa conexión la función y devuelve el intervalo en el que se deberá volver a ejecutar la función para dicha conexión

#Si la conexión lleva activa más que ALERT_INTERVAL, se escribirá la conexión en el fichero de logs y se indicará que se vuelva a ejecutar la función después de que transcurra ALERT_INTERVAL

#SI la conexión lleva activa menos que ALERT_INTERVAL, no se escribirá la conexión en logs y se indicará que se vuelva a ejecutar la función transcurrido ALERT_INTERVAL-duración  (De esta forma se escribirá la conexión cuando alcance ALERT_INTERVAL segundos activa)


			if ( c$duration >= ALERT_INTERVAL )
				{
					#print  "connection writted", c$id, c$duration;
					Conn::set_conn_log_data_hack(c);
			                Log::write(OpenConnection::LOG, c$conn);
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
#Se inicia una conexión y empieza a observarse con ConnPolling::watch -> se observa la conexión c, se ejecutará la función long_callback después de transcurrir ALERT_INTERVAL (tiempo) desde que se inició y dicha función se volverá a ejecutar según lo devuelto por ella misma
                ConnPolling::watch(c, long_callback, 1, ALERT_INTERVAL);
        }

event connection_state_remove(c: connection)
	{
		if ( c$duration < ALERT_INTERVAL )
				{
					#print  "connection writted", c$id, c$duration;
					Conn::set_conn_log_data_hack(c);
			                Log::write(OpenConnection::LOG, c$conn);
				}
}
