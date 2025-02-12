# NEONSCAN

**NEONSCAN** è un tool futuristico per il pentesting, realizzato per essere utilizzato su Kali Linux.  
Questa versione avanzata include le seguenti funzionalità:

- **Banner Futuristico:** Visualizza la scritta "NEONSCAN" in ASCII art all’avvio.
- **Ping Scan:** Invia pacchetti ICMP per verificare la raggiungibilità del target.
- **Port Scan:** Scansiona un intervallo di porte (default da 20 a 1024) utilizzando scansione parallela per maggiore velocità.
- **Banner Grabbing:** Per le porte aperte, tenta di recuperare il banner del servizio.
- **DNS Lookup:** Risolve un dominio, mostrando hostname, alias e indirizzi IP.
- **Traceroute:** Esegue un traceroute verso il target.
- **Subnet Scan:** Se il target è un subnet in formato CIDR (es. `192.168.1.0/24`), esegue un ping sweep per individuare gli host attivi.

## Requisiti

- Python 3.6 o superiore
- [pyfiglet](https://pypi.org/project/pyfiglet/)

## Installazione

1. **Clona il repository:**

   ```bash
   git clone https://github.com/tuo_username/neonscan.git
