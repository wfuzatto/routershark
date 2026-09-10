# RouterOS 7 - altere SERVER_IP e opcionalmente filter-interface.
/tool sniffer set streaming-enabled=yes streaming-server=SERVER_IP streaming-port=37008 filter-stream=yes only-headers=no
/tool sniffer start
