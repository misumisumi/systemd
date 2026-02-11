/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include "networkd-forward.h"
#include "vlan-util.h"

#define BRIDGE_VLAN_BITMAP_MAX 4096
#define BRIDGE_VLAN_BITMAP_LEN (BRIDGE_VLAN_BITMAP_MAX / 32)

#define BRIDGE_VLAN_KEEP_PVID   UINT16_MAX
#define BRIDGE_VLAN_REMOVE_PVID (UINT16_MAX - 1)
assert_cc(BRIDGE_VLAN_REMOVE_PVID > VLANID_MAX);

typedef struct {
        uint16_t vid_start;
        uint16_t vid_end;
        uint32_t vni_start;
        uint32_t vni_end;
        bool is_configured;
} BridgeVLANTunnelEntry;

typedef struct {
        BridgeVLANTunnelEntry *entries;
        size_t n_entries;
} BridgeVLANTunnelVNI;

void network_adjust_bridge_vlan(Network *network);

int bridge_vlan_set_message(Link *link, sd_netlink_message *m, bool is_set);
int bridge_vlan_set_tunnel_message(Link *link, sd_netlink_message *m, bool is_set);

int link_update_bridge_vlan(Link *link, sd_netlink_message *m);
int link_update_bridge_vlan_tunnel_info(Link *link, sd_netlink_message *m);

void bridge_vlan_mark_tunnel_vni_configured(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_id);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_id_range);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_tunnel_vni);
