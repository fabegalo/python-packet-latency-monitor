from scapy.all import *
import matplotlib.pyplot as plt
import matplotlib.animation as animation


class Packet:
    def __init__(self, timestamp, latency, interface, ip_source, ip_destination, protocol):
        self.timestamp = timestamp
        self.latency = latency
        self.packet_len = None
        self.interface = interface
        self.ip_source = ip_source
        self.ip_destination = ip_destination
        self.protocol = protocol


packets = []

fig, axs = plt.subplots(2, 1)
ax1, ax2 = axs

# Primeiro gráfico
xdata, ydata = [], []
line, = ax1.plot([], [], lw=2)

# Segundo gráfico
xdata2, ydata2 = [], []
line2, = ax2.plot([], [], lw=2)

# ======== Limitador de pacotes ===========
# solicita ao usuário que informe o valor maximo de pacotes na tela
graph_delete_after = int(input("Informe o valor maximo de pacotes na tela: "))

# Tratamento de erro do input
if graph_delete_after <= 1:
    graph_delete_after = 2

# inicializa a variável count_extra_reset_graph
count_extra_reset_graph = 0


def update(i):
    global graph_delete_after, count_extra_reset_graph

    pkts = sniff(timeout=0.1, filter="ip")

    for packet in pkts:
        if IP in packet:
            lat = packet.time - packets[-1].timestamp if packets else 0
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            proto = packet[IP].proto

            if proto == 6:
                proto = "TCP"
            elif proto == 17:
                proto = "UDP"
            else:
                proto = proto

            packets.append(Packet(packet.time, lat, packet.name, ip_src, ip_dst, proto))
            packets[-1].packet_len = len(packet)

            if len(ydata) >= graph_delete_after:
                ydata.pop(0)
                xdata.pop(0)
                count_extra_reset_graph += 1

            ydata.append(lat)
            xdata.append(count_extra_reset_graph + len(ydata))
    line.set_data(xdata, ydata)

    ax1.relim()
    ax1.autoscale_view()

    ax2.relim()
    ax2.autoscale_view()

    ax2.clear()
    ax2.axis('off')

    table_data = {}

    for p in packets[-graph_delete_after:]:
        if p.interface in table_data:
            table_data[p.ip_source].append([p.interface, p.protocol, p.ip_destination, p.latency, p.packet_len])
        else:
            table_data[p.ip_source] = [[p.interface, p.protocol, p.ip_destination, p.latency, p.packet_len]]

    table_rows = []

    for ip_src, data in table_data.items():
        interface = ','.join(str(d[0]) for d in data)
        protocol = ','.join(str(d[1]) for d in data)
        ip_dst = ','.join(str(d[2]) for d in data)
        latencies = [d[3] for d in data]
        packet_lens = [d[4] for d in data]
        avg_latency = sum(latencies) / len(latencies)
        avg_packet_len = sum(packet_lens) / len(packet_lens)
        table_rows.append([f"{interface}", f"{protocol}", f"{ip_src}", f"{ip_dst}", f"{avg_latency:.2f} ms",
                           f"{avg_packet_len:.2f} bytes"])

    if table_rows:
        table = ax2.table(cellText=table_rows,
                          colLabels=["Interface", "Protocolo", "IP Origem", "IP Destino", "Latência", "Tamanho"],
                          cellLoc='left', loc='center')
        table.auto_set_font_size(False)
        table.set_fontsize(8)
        table.scale(1, 1.5)

    return line, line2


ani = animation.FuncAnimation(fig, update, interval=100)

ax1.set_title("Análise de Latência em Pacotes")
ax1.set_xlabel('Numero de Pacotes')
ax1.set_ylabel('Latência (ms)')

plt.show()
