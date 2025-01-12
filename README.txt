
   /////////////////////////////////////
  /// ARP SPOOFING/POISONING ATTACK ///
 /////////////////////////////////////

Overview:
    The purpose of this script is to assist in conduct a MITM (Man-In-The-Middle) attack.
    The idea is to find two devices that communicate with each other and force them to
    redirect their traffic to you, the attacker.

    Most often, one will target a perimeter device (Such as a Wi-Fi Router) and then a
    standard workstation. You want to capture the traffic being sent from that device
    and the response traffic coming into the network from the Router/Access Point.

How it works?
    All IPv4-supporting devices will have an ARP Cache. This cache is designed to map
    devices, via their IPv4 address, to their respective MAC address.

    In an ARP Poisoning attack, the attack forges ARP-Response packets. A packet is
    sent to a workstation on behalf of the router, however the MAC of the router is
    replaced with the attacker's MAC address. Likewise, another packet is sent to the
    router on behalf of workstation, and similarly, the MAC of the workstation is
    replaced to be the attackers.

    At this point, both the Router and workstation think each other's MAC address is
    correct, however both MACs point to the attacker's machine. Any time traffic is sent
    it is passed to the attacker's machine first. It is up to the attacker to forward
    this traffic to either device or not.

    This script will continuously send forged ARP responses as the cache of these devices
    have a limit and will auto-reset after a while. In order to keep a successful MITM
    attack going, these forged ARP responses will have to continuously be sent out. 

Features:
    The attacker does NOT need to know the MAC address of either device. An ARP probe will
    be sent to the broadcast address on behalf of the attacker and will capture both MAC
    addresses. This is part of the auto-resolution feature.

    After the attack is sent, the values of both ARP tables on each device will properly
    be reset to their defaults and traffic will flow again as originally intended.

Requirements?
    Root privileges and a BASH terminal.
