/* udp-server.c (contiki-ng3: detection + isolation + metrics) */
#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/energest.h"
#include "sys/log.h"
#include "sys/etimer.h"
#include <inttypes.h>

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_WARN

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT    8765
#define UDP_SERVER_PORT    5678

#define DETECTION_INTERVAL (10 * CLOCK_SECOND)
#define SIM_TIME           (600 * CLOCK_SECOND)
#define PACKET_THRESHOLD   50

static struct simple_udp_connection udp_conn;

static uint32_t packet_count = 0;
static uint32_t node_packet_count[256];

static uint8_t attacker_detected = 0;
static uint8_t attacker_node_id = 0;
static uint32_t dropped_packets = 0;

/* Inter-packet gap */
static uint32_t last_arrival = 0;
static uint64_t total_intergap = 0;
static uint32_t intergap_samples = 0;

PROCESS(udp_server_process, "UDP server");
AUTOSTART_PROCESSES(&udp_server_process);

/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  uint8_t node_id = sender_addr->u8[15];
  uint32_t now = (uint32_t)clock_time();

  packet_count++;
  node_packet_count[node_id]++;

  if(last_arrival != 0) {
    total_intergap += (uint64_t)(now - last_arrival);
    intergap_samples++;
  }
  last_arrival = now;

  if(attacker_detected && node_id == attacker_node_id) {
    dropped_packets++;
    return;
  }

#if WITH_SERVER_REPLY
  simple_udp_sendto(&udp_conn, data, datalen, sender_addr);
#endif
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  static struct etimer detect_timer, sim_timer;

  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();

  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);

  etimer_set(&detect_timer, DETECTION_INTERVAL);
  etimer_set(&sim_timer, SIM_TIME);

  while(1) {
    PROCESS_WAIT_EVENT();

    if(etimer_expired(&detect_timer)) {

      for(int i = 0; i < 256; i++) {
        if(node_packet_count[i] > PACKET_THRESHOLD && !attacker_detected) {
          attacker_node_id = (uint8_t)i;
          attacker_detected = 1;
          LOG_WARN("ATTACKER DETECTED: Node %d\n", i);
          LOG_WARN("Node %d is now ISOLATED\n", i);
        }
        node_packet_count[i] = 0;
      }

      etimer_reset(&detect_timer);
    }

    if(etimer_expired(&sim_timer)) {

      energest_flush();

      LOG_WARN("==== FINAL SERVER METRICS (10 minutes) ====\n");
      LOG_WARN("Total packets received: %" PRIu32 "\n", packet_count);
      LOG_WARN("Total packets dropped (isolation): %" PRIu32 "\n", dropped_packets);

      if(intergap_samples > 0) {
        uint64_t avg_gap = total_intergap / intergap_samples;
        LOG_WARN("Average inter-packet gap (ticks): %" PRIu64 "\n", avg_gap);
      }

      uint64_t tx_time = energest_type_time(ENERGEST_TYPE_TRANSMIT);
      uint64_t rx_time = energest_type_time(ENERGEST_TYPE_LISTEN);
      LOG_WARN("Server ENERGEST TX time: %" PRIu64 "\n", tx_time);
      LOG_WARN("Server ENERGEST RX time: %" PRIu64 "\n", rx_time);

      break;
    }
  }

  PROCESS_END();
}
