#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include <stdint.h>
#include <inttypes.h>
#include "sys/log.h"
#include "net/linkaddr.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define SEND_INTERVAL (10 * CLOCK_SECOND)
#define SIM_TIME      (600 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

static uint32_t tx_count = 0;
static uint32_t rx_count = 0;
static uint32_t missed_tx_count = 0;

/* RTT */
static uint32_t last_send_time = 0;
static uint64_t total_rtt = 0;
static uint32_t rtt_samples = 0;

PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
  uint32_t now = clock_time();
  uint32_t rtt = now - last_send_time;

  total_rtt += rtt;
  rtt_samples++;
  rx_count++;
}

PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer, sim_timer;
  static char str[32];
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);
  etimer_set(&sim_timer, SIM_TIME);

  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer) ||
                             etimer_expired(&sim_timer));

    if(etimer_expired(&periodic_timer)) {

      if(NETSTACK_ROUTING.node_is_reachable() &&
         NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {

        last_send_time = clock_time();

        snprintf(str, sizeof(str), "hello %" PRIu32 "", tx_count);
        simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);
        tx_count++;

      } else {
        if(tx_count > 0) missed_tx_count++;
      }

      /* Flooding logic */
      if(linkaddr_node_addr.u8[7] == 16 ||linkaddr_node_addr.u8[7]==14) {
        etimer_set(&periodic_timer, CLOCK_SECOND / 10);
      } else {
        etimer_set(&periodic_timer,
          SEND_INTERVAL - CLOCK_SECOND +
          (random_rand() % (2 * CLOCK_SECOND)));
      }
    }

    if(etimer_expired(&sim_timer)) {

      LOG_INFO("==== CLIENT FINAL METRICS (10 min) ====\n");
      LOG_INFO("Packets Sent: %" PRIu32 "\n", tx_count);
      LOG_INFO("Packets Received: %" PRIu32 "\n", rx_count);

      if(tx_count > 0) {
        float pdr = (float)rx_count / (float)tx_count;
        LOG_INFO("PDR: %.2f\n", pdr);
        LOG_INFO("Packet Loss: %" PRIu32 "\n", tx_count - rx_count);
      }

      if(rtt_samples > 0) {
        uint32_t avg_rtt = total_rtt / rtt_samples;
        LOG_INFO("Average RTT (ticks): %" PRIu32 "\n", avg_rtt);
      }

      break;
    }
  }

  PROCESS_END();
}
