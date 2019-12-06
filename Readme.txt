implemented console sniffer using raw sockets
examples of using:
python3 sniffer
information about received packets is displayed on stdout
python3 sniffer -o out.txt
information about received packets is output to a file in pcap format
Что сказал делать препод
    1.Предусмотреть возможность фильтрации пакетов
    2.Вывод: настройка подробности отображения
    а-ля hexdump(Сделано)
    3.Сохранение в формат .pcap(Сделано)
    (*)
	4.Подправить вывод(Сделано)
	5.Добавить возможность в NetworkSniffer читать данные из буффера(что то с read)

