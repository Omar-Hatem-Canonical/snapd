# Packet Tagging Code in snapd Repository

This document provides a comprehensive overview of all packet tagging related code found in the snapd repository.

## Overview

Packet tagging in snapd is primarily implemented through BPF (Berkeley Packet Filter) functionality and network interface controls. The code allows for tagging network packets for traffic control, quality of service (QoS), and network isolation purposes.

## Main Locations

### 1. BPF Headers and Definitions

#### File: `/cmd/libsnap-confine-private/bpf/vendor/linux/bpf.h`

This file contains the core BPF packet tagging functionality imported from the Linux kernel.

**Key Functions:**

##### `bpf_get_cgroup_classid()` (Line 1784-1808)
```c
u32 bpf_get_cgroup_classid(struct sk_buff *skb)
```
- **Purpose**: Retrieve the classid for the current task (net_cls cgroup)
- **Description**: The net_cls cgroup provides an interface to tag network packets based on a user-provided identifier for all traffic coming from tasks belonging to the related cgroup
- **Usage**: TC egress path only (not on ingress)
- **Version**: cgroups v1 only
- **Kernel Config**: Requires `CONFIG_CGROUP_NET_CLASSID`
- **Return**: The classid, or 0 for the default unconfigured classid
- **Documentation**: See Linux kernel `Documentation/admin-guide/cgroup-v1/net_cls.rst`

##### `bpf_get_route_realm()` (Line 1978-2000)
```c
u32 bpf_get_route_realm(struct sk_buff *skb)
```
- **Purpose**: Retrieve the realm or route tag (tclassid field)
- **Description**: Similar to net_cls cgroup tagging, but the tag is held by a route (destination entry) rather than a task
- **Usage**: Works with clsact TC egress hook or conventional classful egress qdiscs
- **Kernel Config**: Requires `CONFIG_IP_ROUTE_CLASSID`
- **Return**: The realm of the route for the packet, or 0 if none found

##### `bpf_skb_cgroup_classid()` (Line 4486-4493)
```c
u64 bpf_skb_cgroup_classid(struct sk_buff *skb)
```
- **Purpose**: Alternative to `bpf_get_cgroup_classid()`
- **Difference**: Retrieves the cgroup v1 net_cls class only from the skb's associated socket instead of the current process
- **Return**: The id or 0 if it could not be retrieved

##### `bpf_skb_vlan_push()` (Line 1810-1824)
```c
long bpf_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)
```
- **Purpose**: Push a VLAN tag control information (vlan_tci) to a packet
- **Protocol**: Supports `ETH_P_8021Q` and `ETH_P_8021AD`
- **Side Effect**: Changes underlying packet buffer, invalidating previous pointer checks
- **Return**: 0 on success, negative error on failure

##### `bpf_skb_vlan_pop()` (Line 1826-1836)
```c
long bpf_skb_vlan_pop(struct sk_buff *skb)
```
- **Purpose**: Pop (remove) a VLAN header from a packet
- **Side Effect**: Changes underlying packet buffer
- **Return**: 0 on success, negative error on failure

### 2. Socket Buffer Structure

#### File: `/cmd/libsnap-confine-private/bpf/vendor/linux/bpf.h` (Line 5146-5175)

**`struct __sk_buff`** - User-accessible mirror of in-kernel sk_buff with packet tagging fields:

```c
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;              // Generic packet mark/tag
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;      // VLAN tag present flag
    __u32 vlan_tci;          // VLAN Tag Control Information
    __u32 vlan_proto;        // VLAN protocol
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;          // Traffic control index
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;        // Traffic control classid for tagging
    __u32 data;
    __u32 data_end;
    // ... additional fields
};
```

**Key Tagging Fields:**
- **`mark`**: Generic packet mark for iptables/netfilter tagging
- **`vlan_tci`**: VLAN Tag Control Information (includes priority and VLAN ID)
- **`vlan_present`**: Boolean flag indicating if VLAN tag is present
- **`vlan_proto`**: VLAN protocol type
- **`tc_classid`**: Traffic control class identifier for QoS tagging
- **`tc_index`**: Traffic control index

### 3. BPF Instructions

#### File: `/cmd/libsnap-confine-private/bpf/bpf-insn.h` (Line 142-160)

Macros for direct packet access (useful for packet tagging operations):

```c
/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */
#define BPF_LD_ABS(SIZE, IMM)

/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */
#define BPF_LD_IND(SIZE, SRC, IMM)
```

These allow reading and potentially modifying packet headers for tagging purposes.

### 4. Interface Permissions and Network Control

#### File: `/interfaces/builtin/network_control.go` (Line 181)

Grants `network packet` capability for packet-level network operations:

```go
network packet,
```

This AppArmor permission allows snaps with the network-control interface to:
- Create raw sockets
- Perform packet-level network operations
- Implement custom packet tagging and filtering

#### File: `/interfaces/builtin/network_manager.go` (Line 59)

NetworkManager interface also includes packet network access:

```go
network packet,
```

#### File: `/interfaces/builtin/ofono.go` (Line 88)

Ofono (telephony) interface includes packet network access:

```go
network packet,
```

### 5. Cgroup Network Classifier References

#### File: `/interfaces/builtin/greengrass_support.go` (Line 136-138)

References to net_cls cgroup for packet classification:

```go
# separated from the above rule for clarity due to the comma in "net_cls,net_prio"
owner /old_rootfs/sys/fs/cgroup/net_cls,net_prio/{,system.slice/}system.slice/ rw,
owner /old_rootfs/sys/fs/cgroup/net_cls,net_prio/{,system.slice/}system.slice/[0-9a-f].../{,**} rw,
```

Allows access to the net_cls (network classifier) cgroup which is used for packet tagging.

#### File: `/sandbox/cgroup/cgroup_test.go` (Lines 133, 242)

Test cases referencing net_cls cgroup:

```
8:net_cls,net_prio:/
6:net_cls,net_prio:/
```

### 6. Firewall Control VLAN Support

#### File: `/interfaces/builtin/firewall_control.go` (Line 125)

Access to bridge VLAN filtering:

```go
@{PROC}/sys/net/bridge/bridge-nf-filter-vlan-tagged rw,
```

Allows control of VLAN-tagged packet filtering in network bridges.

### 7. Network Library Configuration

#### File: `/interfaces/apparmor/template.go` (Line 176)

Access to libnl-3 packet classification configuration:

```go
/etc/libnl-3/{classid,pktloc} r,      // apps that use libnl
```

These files contain:
- **`classid`**: Class identifier mappings for packet classification
- **`pktloc`**: Packet location definitions for parsing

## Packet Tagging Types in snapd

### 1. **Cgroup-based Tagging (net_cls)**
- Tags packets based on the cgroup of the originating process
- Used for per-application traffic shaping and accounting
- Works with cgroups v1 only

### 2. **VLAN Tagging**
- IEEE 802.1Q VLAN tags for network segmentation
- Supports push/pop operations on packet tags
- Includes priority and VLAN ID in vlan_tci field

### 3. **Traffic Control (tc) Classification**
- tc_classid field for QoS and traffic shaping
- Used with Linux traffic control subsystem
- Supports route realms for routing-based tagging

### 4. **Generic Packet Marking**
- Socket buffer mark field for netfilter/iptables
- Used for policy routing and connection tracking
- Can be set/read by BPF programs

## Use Cases in snapd

1. **Container Networking**: Tag packets from different snap containers for isolation and QoS
2. **Traffic Shaping**: Apply bandwidth limits based on cgroup classification
3. **Network Isolation**: Use VLAN tags to separate snap network traffic
4. **Security Policies**: Mark packets for firewall rules and filtering
5. **Monitoring**: Tag packets for accounting and network flow analysis

## Kernel Requirements

To use packet tagging features:
- `CONFIG_CGROUP_NET_CLASSID=y` - For cgroup-based tagging
- `CONFIG_IP_ROUTE_CLASSID=y` - For route realm tagging
- BPF support in the kernel
- Traffic control (tc) subsystem

## Related Documentation

- Linux Kernel: `Documentation/admin-guide/cgroup-v1/net_cls.rst`
- Linux Kernel BPF documentation
- tc-bpf(8) man page
- iptables/netfilter documentation for packet marking

## Summary

The snapd repository contains comprehensive packet tagging support through:
1. BPF helper functions for reading/writing packet tags
2. Socket buffer structures with multiple tagging fields
3. Interface permissions for packet-level network operations
4. Cgroup integration for per-application tagging
5. VLAN tag manipulation capabilities
6. Traffic control classification support

This infrastructure enables fine-grained network control, QoS, security policies, and network isolation for snaps.
