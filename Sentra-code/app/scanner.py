# # import socket
# # import threading
# # import time

# # # Timeout for connections
# # TIMEOUT = 1.5

# # # Function for scanning a single port and grabbing banner
# # def scan_tcp(target, port):
# #     try:
# #         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #         sock.settimeout(TIMEOUT)
# #         result = sock.connect_ex((target, port))
# #         if result == 0:  # If port is open
# #             banner = grab_banner(sock)
# #             return f"Port {port} is open, Banner: {banner}"
# #         else:
# #             return f"Port {port} is closed"
# #     except socket.error:
# #         return f"Port {port} is filtered or closed"
# #     finally:
# #         sock.close()

# # # Function for scanning UDP ports (basic check)
# # def scan_udp(target, port):
# #     try:
# #         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# #         sock.settimeout(TIMEOUT)
# #         sock.sendto(b"", (target, port))  # Send an empty packet
# #         sock.recvfrom(1024)  # Waiting for response
# #         return f"Port {port} is open (UDP)"
# #     except socket.timeout:
# #         return f"Port {port} is closed or filtered (UDP)"
# #     except socket.error:
# #         return f"Port {port} is filtered or closed (UDP)"
# #     finally:
# #         sock.close()

# # # Banner grabbing from a TCP socket
# # def grab_banner(sock):
# #     try:
# #         sock.settimeout(TIMEOUT)
# #         banner = sock.recv(1024).decode().strip()  # Try to grab the banner
# #         return banner if banner else "No banner received"
# #     except socket.timeout:
# #         return "No banner received"
# #     except Exception as e:
# #         return f"Error grabbing banner: {str(e)}"

# # # Thread function to scan a single port (TCP and UDP)
# # def scan_port(target, port, protocol="tcp"):
# #     if protocol == "tcp":
# #         return scan_tcp(target, port)
# #     elif protocol == "udp":
# #         return scan_udp(target, port)
# #     else:
# #         return "Unsupported protocol"

# # # Function to scan a range of ports (TCP or UDP)
# # def scan_ports(target, port_range, protocol="tcp"):
# #     results = []
# #     for port in port_range:
# #         results.append(scan_port(target, port, protocol))
# #         print(f"Scanning port {port} ({protocol})...")
# #     return results

# # # Function to scan both TCP and UDP ports
# # def scan_all_ports(target, port_range):
# #     tcp_results = scan_ports(target, port_range, protocol="tcp")
# #     udp_results = scan_ports(target, port_range, protocol="udp")
    
# #     return tcp_results + udp_results

# # # Run the scan on a target
# # def run_scan(target, start_port=1, end_port=1024):
# #     port_range = range(start_port, end_port + 1)
# #     # results = scan_all_ports(target, port_range)
# #     results = scan_ports(target,[135,139,445,5357],"tcp")
# #     print("\nScan Results:")
# #     for result in results:
# #         print(result)

# # # Example usage
# # if __name__ == "__main__":
# #     target = "192.168.43.88"  # Replace with the target IP
# #     start_port = 1
# #     end_port = 1024
# #     run_scan(target, start_port, end_port)


# import socket
# import ssl
# from scapy.all import *
# import socket

# # Function to get the service name and version from the open port
# def get_service_info(host, port):
#     try:
#         # Try to establish a socket connection
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(1)  # Set a 1-second timeout for connection

#         # Attempt to connect to the target port
#         sock.connect((host, port))
#         service_info = None

#         # Banner grabbing - try different protocols (HTTP, FTP, etc.)
#         if port == 80:
#             sock.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host.encode()))
#             service_info = sock.recv(1024).decode(errors="ignore")[:100]
#         elif port == 443:
#             context = ssl.create_default_context()
#             conn = context.wrap_socket(sock, server_hostname=host)
#             conn.connect((host, port))
#             service_info = "SSL/TLS Handshake Successful"
#         elif port == 21:
#             service_info = "FTP Service"
#         elif port == 22:
#             service_info = "SSH Service"
        
#         sock.close()
#         return service_info if service_info else "Unknown Service"
#     except Exception as e:
#         return None

# # Function to perform the port scan and return open ports with service details
# def scan_ports(host, port_range=(1, 1024)):
#     open_ports = []
#     for port in range(port_range[0], port_range[1] + 1):
#         # Try to open the port
#         service_info = get_service_info(host, port)
#         if service_info:
#             open_ports.append({
#                 'port': port,
#                 'protocol': 'TCP',
#                 'service': service_info
#             })

#     return open_ports

# # Function to start the scan and print results
# def main(target_host):
#     print(f"Scanning {target_host} for open ports...")
#     open_ports = scan_ports(target_host)

#     if open_ports:
#         print(f"Found {len(open_ports)} open ports:")
#         for port_info in open_ports:
#             print(f"Port {port_info['port']} - {port_info['protocol']} - Service: {port_info['service']}")
#     else:
#         print("No open ports found.")

# # Run the scan (use your target host or IP here)
# if __name__ == "__main__":
#     target = "scanme.nmap.org"  # Replace with your target IP/hostname
#     main(target)
import socket

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.43.88",139))
d = s.recv(4096)
print(d)