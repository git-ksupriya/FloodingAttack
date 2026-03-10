#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include "sys/etimer.h"
#include <inttypes.h>

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_WARN

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define DETECTION_INTERVAL (10 * CLOCK_SECOND)
#define SIM_TIME           (600 * CLOCK_SECOND)
#define PACKET_THRESHOLD   50

static struct simple_udp_connection udp_conn;

/* Window counter */
static uint32_t packet_count = 0;

/* Total counter (10 min) */
static uint32_t total_packets_received = 0;

static uint32_t node_packet_count[256];

/* Inter-packet gap */
static uint32_t last_arrival = 0;
static uint64_t total_intergap = 0;
static uint32_t intergap_samples = 0;

PROCESS(udp_server_process, "UDP server");
AUTOSTART_PROCESSES(&udp_server_process);

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
  uint32_t now = clock_time();

  packet_count++;               // window counter
  total_packets_received++;     // full simulation counter
  node_packet_count[node_id]++;

  if(last_arrival != 0) {
    total_intergap += (uint64_t)(now - last_arrival);
    intergap_samples++;
  }
  last_arrival = now;

  simple_udp_sendto(&udp_conn, data, datalen, sender_addr);
}

PROCESS_THREAD(udp_server_process, ev, data)
{
  static struct etimer detection_timer, sim_timer;

  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();

  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);

  etimer_set(&detection_timer, DETECTION_INTERVAL);
  etimer_set(&sim_timer, SIM_TIME);

  while(1) {

    PROCESS_WAIT_EVENT();

    if(etimer_expired(&detection_timer)) {

      LOG_WARN("---- Detection Window ----\n");
      LOG_WARN("Total packets in window: %" PRIu32 "\n", packet_count);

      for(int i = 0; i < 256; i++) {
        if(node_packet_count[i] > PACKET_THRESHOLD) {
          LOG_WARN("Node %d is FLOODING! Packets: %" PRIu32 "\n",
                   i, node_packet_count[i]);
        }
        node_packet_count[i] = 0;
      }

      packet_count = 0;
      etimer_reset(&detection_timer);
    }

    if(etimer_expired(&sim_timer)) {

      LOG_WARN("==== SERVER FINAL METRICS (10 min) ====\n");

      LOG_WARN("Total packets received (10 min): %" PRIu32 "\n",
               total_packets_received);

      if(intergap_samples > 0) {
        uint64_t avg_gap = total_intergap / intergap_samples;
        LOG_WARN("Average inter-packet gap (ticks): %" PRIu64 "\n", avg_gap);
      }

      break;
    }
  }

  PROCESS_END();
}
