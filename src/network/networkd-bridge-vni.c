/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_link.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-bridge-vlan.h"
#include "networkd-bridge-vni.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"
#include "string-util.h"

static int add_vnifilter_entry(sd_netlink_message *m, uint32_t vni_start, uint32_t vni_end, char **str) {
        int r;

        assert(m);

        if (DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "vni=%u%s%u",
                                                 vni_start,
                                                 vni_end ? "-" : "",
                                                 vni_end ? vni_end : 0);

        r = sd_netlink_message_append_u32(m, VXLAN_VNIFILTER_ENTRY_START, vni_start);
        if (r < 0)
                return r;

        if (vni_end > vni_start) {
                r = sd_netlink_message_append_u32(m, VXLAN_VNIFILTER_ENTRY_END, vni_end);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int bridge_vni_append_set_vnifilter_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *add_str = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        /* Open VXLAN_VNIFILTER_ENTRY container */
        r = sd_netlink_message_open_container(m, VXLAN_VNIFILTER_ENTRY | NLA_F_NESTED);
        if (r < 0)
                return r;

        /* Process configured tunnel VNI entries that are not yet applied */
        for (size_t i = 0; i < link->network->bridge_vlan_tunnel_vni.n_entries; i++) {
                BridgeVLANTunnelEntry *entry = &link->network->bridge_vlan_tunnel_vni.entries[i];

                /* Skip if already configured in the kernel */
                /* if (entry->is_configured) */
                /*         continue; */

                /* Add VNI mapping */
                r = add_vnifilter_entry(m, entry->vni_start, entry->vni_end, &add_str);
                if (r < 0)
                        goto close_container;

                /* Close VXLAN_VNIFILTER_ENTRY container */
                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return r;
        }

        if (add_str)
                log_link_debug(link, "Setting VXLAN VNI ENTRY: %s", add_str);

        return 0;

close_container:
        sd_netlink_message_close_container(m);
        return r;
}

static int bridge_vni_append_del_vnifilter_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *del_str = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        /* Not in config, mark for deletion */
        r = sd_netlink_message_open_container(m, VXLAN_VNIFILTER_ENTRY | NLA_F_NESTED);
        if (r < 0)
                return r;
        /* Delete entries that exist in kernel but not in configuration */
        for (size_t i = 0; i < link->bridge_vlan_tunnel_existing.n_entries; i++) {
                BridgeVLANTunnelEntry *existing = &link->bridge_vlan_tunnel_existing.entries[i];

                /* Check if this entry is in the configured set */
                for (size_t j = 0; j < link->network->bridge_vlan_tunnel_vni.n_entries; j++) {
                        BridgeVLANTunnelEntry *configured = &link->network->bridge_vlan_tunnel_vni.entries[j];
                        if (configured->vni_start == existing->vni_start &&
                            configured->vni_end == existing->vni_end)
                                goto next_existing;
                }


                r = add_vnifilter_entry(m, existing->vni_start, existing->vni_end, &del_str);
                if (r < 0)
                        goto close_container;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        next_existing:
                continue;

close_container:
                sd_netlink_message_close_container(m);
                return r;
        }

        if (del_str)
                log_link_debug(link, "Deleting VXLAN VNIFILTER: %s", del_str);

        return 0;
}

int bridge_vni_set_vnientry_message(Link *link, sd_netlink_message *m, bool is_set) {
        int r;

        assert(link);
        assert(m);

        /* Check if we have TunnelVNI entries or existing entries to delete */
        if ((!link->network->bridge_vlan_tunnel_vni.entries || link->network->bridge_vlan_tunnel_vni.n_entries == 0) &&
            (!link->bridge_vlan_tunnel_existing.entries || link->bridge_vlan_tunnel_existing.n_entries == 0))
                return 0;

        if (is_set)
                r = bridge_vni_append_set_vnifilter_info(link, m);
        else
                r = bridge_vni_append_del_vnifilter_info(link, m);

        return r;
}
