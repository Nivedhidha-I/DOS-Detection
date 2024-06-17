from scapy.all import rdpcap

filename = "Python Code\extract\capture_malariaDoS.pcap"

# keys = [
#   'mqtt.hdrflags', 
#   'mqtt.msg', 
#   'mqtt.msgid', 
#   'mqtt.len', 
#   'tcp.flags', 
#   'mqtt.kalive', 
#   'mqtt.conflag.cleansess', 
#   'mqtt.willmsg_len', 
#   'mqtt.qos', 
#   'tcp.time_delta', 
#   'mqtt.dupflag', 
#   'mqtt.willtopic', 
#   'mqtt.conflags', 
#   'mqtt.protoname', 
#   'tcp.len', 
#   'mqtt.msgtype', 
#   'mqtt.proto_len', 
#   'mqtt.ver'
# ]

keys_of_interest = {
    "TCP": ["flags", "time_delta", "len"],
    "MQTT": [
        "hdrflags", "msg", "msgid", "len", "kalive", "conflag.cleansess",
        "willmsg_len", "qos", "dupflag", "willtopic", "conflags", "protoname",
        "msgtype", "proto_len", "ver"
    ]
}

def extract_details(packet):
  details = {}

  # Check for TCP layer
  if "TCP" in packet:
    tcp_layer = packet["TCP"]
    # Handle potential missing attributes using try-except
    details.update({
        key: getattr(tcp_layer, key) if hasattr(tcp_layer, key) else None
        for key in keys_of_interest["TCP"]
    })

  # Check for presence of payload
  if "payload" in packet:
    payload_layer = packet["payload"]

    # Check if payload layer name matches an MQTT layer (optional)
    if hasattr(payload_layer, "name") and payload_layer.name in keys_of_interest:
      details.update({key: getattr(payload_layer, key) for key in keys_of_interest[payload_layer.name]})
    else:
      # Handle unknown payload layers (optional)
      # You might need additional libraries or logic here if your MQTT data
      # isn't in a standard format within the payload.
      pass

  return details


packets = rdpcap(filename)
print(packets)


filtered_packets = []
for packet in packets:
  details = extract_details(packet)
  if details:  # Only keep packets with extracted details
    filtered_packets.append(details)

print(filtered_packets[:5])


packet = packets[0]  # Assuming packets is a list, access the first packet

tcp_flags = packet["TCP"].flags
print(tcp_flags)

tcp_len = packet.time
print(tcp_len)