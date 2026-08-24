# Flooding Attack Detection and Isolation in IoT Networks

An application-layer mechanism for detecting and isolating flooding
attacks in RPL-based IoT networks.

## Overview

The project uses Contiki/Cooja to simulate an RPL-based sensor network.
Malicious nodes generate abnormal UDP traffic, which is detected and
isolated by the proposed mechanism.

## Experimental Setup

- Simulator: Contiki Cooja
- Network: RPL-based IoT network
- Attack: UDP flooding
- Metrics:
  - Packet Delivery Ratio
  - Packet Loss
  - RTT
  - Routing Overhead

## Results

The isolation mechanism recovered PDR from 0.48 in the attacked scenario
to 0.98 after isolation.
