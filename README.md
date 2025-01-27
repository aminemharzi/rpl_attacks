# IoT Security Attack Implementations in RPL-based Networks

## Overview
This project implements various attacks on RPL-based IoT networks using the Cooja simulator. These attacks aim to simulate real-world security threats, study their effects on network performance, and evaluate potential countermeasures. The attacks included are:

1. **Sybil Attack (SYA)**
2. **Version Number Attack (VNA)**
3. **DIS Flooding Attack (DFA)**
4. **Selective Forwarding Attack (SFA)**

Each attack is implemented through modifications in the `udp-client.c` code and controlled dynamically via Cooja simulation scripts.

---

## Attack 1: Sybil Attack (SYA)

### Description
A Sybil Attack is where a malicious node creates multiple fake identities to disrupt the network. These fake identities can flood the routing tables, leading to instability in the DODAG.

### Implementation Details
- **Activation:** `SYA_on` is set to `1`, and the node begins broadcasting fake identities.
- **Fake IDs:** The `fake_id` variable is updated dynamically at specific intervals.
- **Deactivation:** After a predefined period, `SYA_on` is set to `0`.

### Simulation Script
```javascript
let rand_node = Math.floor(Math.random() * 6);
while (rand_node < 2 || rand_node === 6) {
    rand_node = Math.floor(Math.random() * 6);
}
log.log("SYA Attack Target Node: " + rand_node + "\n");

let sya = new Attack("SYA_on", rand_node, 20, 60);
sya.vName = "fake_id";
sya.valuesList.push(0x09); sya.timesList.push(20);
sya.valuesList.push(0x26); sya.timesList.push(40);
sya.valuesList.push(0x3f); sya.timesList.push(50);

while (true) {
    sya.flipSwitch(time);
    YIELD();
}
```

---

## Attack 2: Version Number Attack (VNA)

### Description
In a Version Number Attack, a malicious node increases the version number in DIO messages to trigger global repairs, disrupting network stability.

### Implementation Details
- **Activation:** `VNA_on` is toggled to `1`, and the node increments the version number of its DODAG.
- **Impact:** This forces neighboring nodes to reset their routing tables and join the DODAG repeatedly.

### Simulation Script
```javascript
let vna = new Attack("VNA_on", 3, 30, 90);

while (true) {
    vna.flipSwitch(time);
    YIELD();
}
```

---

## Attack 3: DIS Flooding Attack (DFA)

### Description
A DIS Flooding Attack involves sending frequent DIS messages to force neighboring nodes to respond with DIO messages, consuming resources.

### Implementation Details
- **Activation:** `DFA_on` is set to `1`, and the node sends DIS messages at short intervals.
- **Deactivation:** The attack stops when `DFA_on` is toggled to `0`.

### Simulation Script
```javascript
let dfa = new Attack("DFA_on", 4, 50, 120);

while (true) {
    dfa.flipSwitch(time);
    YIELD();
}
```

---

## Attack 4: Selective Forwarding Attack (SFA)

### Description
In an SFA, a malicious node selectively drops packets, disrupting communication and affecting packet delivery ratios.

### Implementation Details
- **Activation:** `SFA_on` is toggled to `1`, and the node begins dropping specific packets.
- **Deactivation:** The attack stops when `SFA_on` is toggled to `0`.

### Simulation Script
```javascript
let sfa = new Attack("SFA_on", 5, 40, 100);

while (true) {
    sfa.flipSwitch(time);
    YIELD();
}
```

---

## General Instructions

### Prerequisites
- Contiki-NG installed on your system.
- Cooja simulator properly configured.

### Steps to Run
1. Open the **Cooja Simulator**.
2. Load the `udp-client.c` file into a mote type.
3. Set up the network topology with at least 6 nodes.
4. Add the corresponding simulation script for the desired attack.
5. Start the simulation.

### Expected Outputs
- **Sybil Attack:** The target node broadcasts fake identities, visible in neighbor tables.
- **VNA:** Neighboring nodes continuously reset their routing tables.
- **DFA:** The network is flooded with DIS and DIO messages.
- **SFA:** Packets are selectively dropped, reducing successful transmissions.

---

## Observations
- Each attack demonstrates a unique way of disrupting RPL-based networks.
- The impacts, such as increased resource consumption and instability, are measurable through Cooja logs.

---

## Contributors
- **[Your Name]**: Implementation and documentation.

---

## References
1. [RFC 6550 - RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks](https://tools.ietf.org/html/rfc6550)
2. Research papers on RPL-based attacks in IoT networks.

