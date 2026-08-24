# Flooding Attack Detection and Isolation in IoT Networks

An application-layer mechanism for detecting and isolating flooding
attacks in RPL-based IoT networks.

## Overview

The project uses Contiki/Cooja to simulate an RPL-based sensor network
under three scenarios:

1. **Normal:** The network operates without an attacker.
2. **Attack:** A malicious node generates abnormal UDP traffic, simulating
   a flooding attack.
3. **Isolation:** The flooding attack is detected at the application layer,
   and the sink isolates the attacker by dropping packets received from
   the malicious node.

## Experimental Setup

- Simulator: Contiki Cooja
- Network: RPL-based IoT network
- Attack: UDP flooding
- Mitigation: Application-layer attacker isolation at the sink
- Metrics:
  - Packet Delivery Ratio
  - Packet Loss
  - RTT
  - Routing Overhead

## Results

The isolation mechanism recovered Packet Delivery Ratio (PDR) from
0.48 in the attacked scenario to 0.98 after isolation.
