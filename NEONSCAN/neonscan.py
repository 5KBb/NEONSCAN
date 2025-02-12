#!/usr/bin/env python3
import pyfiglet
import argparse
import subprocess
import socket
import sys
import re
import ipaddress
import concurrent.futures

def print_banner():
    """
    Stampa il banner con la scritta 'NEONSCAN' in stile futuristico.
    Utilizza il font 'digital' con fallback a 'slant' in caso di errore.
    """
    try:
        banner = pyfiglet.figlet_format("NEONSCAN", font="digital")
    except Exception:
        banner = pyfiglet.figlet_format("NEONSCAN", font="slant")
    print(banner)

def ping_target(target):
    """
    Esegue un ping sul target utilizzando il comando di sistema.
    Su Linux viene usato "ping -c 4" per inviare 4 pacchetti.
    """
    print("\n[*] Esecuzione del Ping Scan su {}".format(target))
    try:
        result = subprocess.run(["ping", "-c", "4", target], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print("Errore durante il ping: ", e)

def port_scan(target, start, end):
    """
    Esegue una scansione delle porte sul target, dall'intervallo 'start' a 'end'.
    Utilizza un pool di thread per accelerare la scansione.
    Restituisce una lista delle porte aperte.
    """
    print("\n[*] Esecuzione del Port Scan su {} (Intervallo: {}-{})".format(target, start, end))
    open_ports = []

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return port
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, port): port for port in range(start, end + 1)}
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port is not None:
                print("Porta {}: Aperta".format(port))
                open_ports.append(port)
    return open_ports

def banner_grab(target, port):
    """
    Tenta di recuperare il banner del servizio in ascolto sulla porta specificata.
    Se la porta è 80 o 443 invia una richiesta HTTP minimale.
    """
    print("\n[*] Tentativo di Banner Grabbing sulla porta {}".format(port))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        # Se si tratta di una porta web, invia una richiesta HTTP
        if port in [80, 443]:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        try:
            banner = sock.recv(1024)
            if banner:
                print("Banner per la porta {}:\n{}".format(port, banner.decode(errors='ignore')))
            else:
                print("Nessun banner ricevuto per la porta {}".format(port))
        except socket.timeout:
            print("Timeout durante il banner grabbing sulla porta {}".format(port))
        sock.close()
    except Exception as e:
        print("Errore durante il banner grabbing sulla porta {}: {}".format(port, e))

def dns_lookup(target):
    """
    Esegue un DNS lookup sul target (se è un dominio).
    Mostra hostname, eventuali alias e indirizzi IP.
    """
    print("\n[*] Esecuzione del DNS Lookup per {}".format(target))
    try:
        host_info = socket.gethostbyname_ex(target)
        print("Hostname: {}".format(host_info[0]))
        if host_info[1]:
            print("Alias: {}".format(", ".join(host_info[1])))
        print("Indirizzi IP: {}".format(", ".join(host_info[2])))
    except Exception as e:
        print("Errore durante il DNS lookup: ", e)

def traceroute(target):
    """
    Esegue il traceroute verso il target utilizzando il comando di sistema.
    Su Kali Linux il comando utilizzato è 'traceroute'.
    """
    print("\n[*] Esecuzione del Traceroute verso {}".format(target))
    try:
        result = subprocess.run(["traceroute", target], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print("Errore durante il traceroute: ", e)

def ping_host(ip):
    """
    Esegue un ping singolo verso un host.
    Restituisce True se il host risponde, False altrimenti.
    """
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        if "1 received" in result.stdout or "1 packets received" in result.stdout:
            return True
    except Exception:
        pass
    return False

def subnet_scan(subnet):
    """
    Esegue una scansione di un intero subnet (in formato CIDR) inviando un ping ad ogni host.
    Utilizza thread per eseguire la scansione in parallelo.
    Restituisce la lista degli host attivi.
    """
    print("\n[*] Esecuzione del Subnet Scan su {}".format(subnet))
    live_hosts = []
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in network.hosts()}
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                if future.result():
                    print("Host attivo: {}".format(ip))
                    live_hosts.append(str(ip))
        if not live_hosts:
            print("Nessun host attivo trovato nel subnet {}".format(subnet))
        return live_hosts
    except Exception as e:
        print("Errore durante il subnet scan: ", e)
        return []

def main():
    parser = argparse.ArgumentParser(
        description="NEONSCAN - Tool futuristico per pentesting su Kali Linux"
    )
    parser.add_argument("-t", "--target", 
                        help="Indirizzo IP, dominio o subnet (in CIDR) da analizzare", 
                        required=True)
    parser.add_argument("--ping", action="store_true", 
                        help="Esegui un ping scan sul target")
    parser.add_argument("--port-scan", action="store_true", 
                        help="Esegui un port scan sul target")
    parser.add_argument("--port-range", default="20-1024", 
                        help="Intervallo di porte da scansionare (default: 20-1024). Formato: inizio-fine")
    parser.add_argument("--banner", action="store_true", 
                        help="Esegui il banner grabbing sulle porte aperte (richiede --port-scan)")
    parser.add_argument("--dns", action="store_true", 
                        help="Esegui il DNS lookup sul target (se è un dominio)")
    parser.add_argument("--traceroute", action="store_true", 
                        help="Esegui il traceroute verso il target")
    parser.add_argument("--subnet-scan", action="store_true", 
                        help="Esegui una scansione del subnet (target deve essere in formato CIDR, es: 192.168.1.0/24)")
    
    args = parser.parse_args()
    print_banner()
    target = args.target

    # Se è richiesta la scansione di un subnet, esegui il ping sweep
    if args.subnet_scan:
        live_hosts = subnet_scan(target)
        print("\nHost attivi trovati: {}".format(", ".join(live_hosts)))
        return

    # Se il target non è un subnet, risolvi in IP (se necessario)
    try:
        target_ip = socket.gethostbyname(target)
        print("[*] Target risolto in IP: {}\n".format(target_ip))
    except Exception as e:
        print("Errore nella risoluzione del target: ", e)
        sys.exit(1)

    if args.dns:
        dns_lookup(target)

    if args.ping:
        ping_target(target_ip)

    if args.traceroute:
        traceroute(target)

    if args.port_scan:
        match = re.match(r"(\d+)-(\d+)", args.port_range)
        if match:
            start_port = int(match.group(1))
            end_port = int(match.group(2))
        else:
            print("Intervallo di porte non valido. Usa il formato inizio-fine (es. 20-1024).")
            sys.exit(1)
        open_ports = port_scan(target_ip, start_port, end_port)
        if args.banner:
            for port in open_ports:
                banner_grab(target_ip, port)
    
    if not (args.ping or args.port_scan or args.dns or args.traceroute or args.subnet_scan):
        print("Nessuna funzionalità di scanning selezionata. Specifica almeno una opzione come --ping, --port-scan, --dns, --traceroute o --subnet-scan.")

if __name__ == "__main__":
    main()
