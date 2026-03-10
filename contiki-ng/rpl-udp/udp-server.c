#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include <inttypes.h>

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define SIM_TIME (600 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

static uint32_t total_packets_received = 0;

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
  uint32_t now = clock_time();

  total_packets_received++;

  if(last_arrival != 0) {
    total_intergap += (uint64_t)(now - last_arrival);
    intergap_samples++;
  }
  last_arrival = now;

#if WITH_SERVER_REPLY
  simple_udp_sendto(&udp_conn, data, datalen, sender_addr);
#endif
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  static struct etimer sim_timer;

  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();

  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);

  etimer_set(&sim_timer, SIM_TIME);

  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&sim_timer));

    LOG_INFO("==== BASELINE SERVER FINAL METRICS (10 min) ====\n");
    LOG_INFO("Total packets received: %" PRIu32 "\n",
             total_packets_received);

    if(intergap_samples > 0) {
      uint64_t avg_gap = total_intergap / intergap_samples;
      LOG_INFO("Average inter-packet gap (ticks): %" PRIu64 "\n", avg_gap);
    }

    break;
  }

  PROCESS_END();
}
