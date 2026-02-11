/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include <linux/if_bridge.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-bridge-vlan.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "netdev/vxlan.h"
#include "parse-util.h"
#include "string-util.h"
#include "vlan-util.h"

static bool is_bit_set(unsigned nr, const uint32_t *addr) {
        assert(nr < BRIDGE_VLAN_BITMAP_MAX);
        return addr[nr / 32] & (UINT32_C(1) << (nr % 32));
}

static void set_bit(unsigned nr, uint32_t *addr) {
        assert(nr < BRIDGE_VLAN_BITMAP_MAX);
        addr[nr / 32] |= (UINT32_C(1) << (nr % 32));
}

static int add_single(sd_netlink_message *m, uint16_t id, bool untagged, bool is_pvid, char **str) {
        assert(m);
        assert(id < BRIDGE_VLAN_BITMAP_MAX);

        if (DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "%u%s%s%s%s%s", id,
                                                 (untagged || is_pvid) ? "(" : "",
                                                 untagged ? "untagged" : "",
                                                 (untagged && is_pvid) ? "," : "",
                                                 is_pvid ? "pvid" : "",
                                                 (untagged || is_pvid) ? ")" : "");

        return sd_netlink_message_append_data(m, IFLA_BRIDGE_VLAN_INFO,
                                              &(struct bridge_vlan_info) {
                                                      .vid = id,
                                                      .flags = (untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0) |
                                                               (is_pvid ? BRIDGE_VLAN_INFO_PVID : 0),
                                              },
                                              sizeof(struct bridge_vlan_info));
}

static int add_range(sd_netlink_message *m, uint16_t begin, uint16_t end, bool untagged, char **str) {
        int r;

        assert(m);
        assert(begin <= end);
        assert(end < BRIDGE_VLAN_BITMAP_MAX);

        if (begin == end)
                return add_single(m, begin, untagged, /* is_pvid = */ false, str);

        if (DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "%u-%u%s", begin, end, untagged ? "(untagged)" : "");

        r = sd_netlink_message_append_data(m, IFLA_BRIDGE_VLAN_INFO,
                                           &(struct bridge_vlan_info) {
                                                   .vid = begin,
                                                   .flags = (untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0) |
                                                            BRIDGE_VLAN_INFO_RANGE_BEGIN,
                                           },
                                           sizeof(struct bridge_vlan_info));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(m, IFLA_BRIDGE_VLAN_INFO,
                                           &(struct bridge_vlan_info) {
                                                   .vid = end,
                                                   .flags = (untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0) |
                                                            BRIDGE_VLAN_INFO_RANGE_END,
                                           },
                                           sizeof(struct bridge_vlan_info));
        if (r < 0)
                return r;

        return 0;
}

static int add_tunnel_info(sd_netlink_message *m, uint16_t vid, uint32_t vni, uint16_t flags, char **str) {
        int r;

        assert(m);

        if (DEBUG_LOGGING)
                (void) strextendf_with_separator(str, ",", "%u->%u%s",
                                                 vid, vni,
                                                 flags ? (flags == BRIDGE_VLAN_INFO_RANGE_BEGIN ? "(range_begin)" : "(range_end)") : "");

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_VID, vid);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_BRIDGE_VLAN_TUNNEL_ID, vni);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, flags);
        if (r < 0)
                return r;

        return 0;
}

static uint16_t link_get_pvid(Link *link, bool *ret_untagged) {
        assert(link);
        assert(link->network);

        if (vlanid_is_valid(link->network->bridge_vlan_pvid)) {
                if (ret_untagged)
                        *ret_untagged = is_bit_set(link->network->bridge_vlan_pvid,
                                                   link->network->bridge_vlan_untagged_bitmap);
                return link->network->bridge_vlan_pvid;
        }

        if (link->network->bridge_vlan_pvid == BRIDGE_VLAN_KEEP_PVID) {
                if (ret_untagged)
                        *ret_untagged = link->bridge_vlan_pvid_is_untagged;
                return link->bridge_vlan_pvid;
        }

        if (ret_untagged)
                *ret_untagged = false;
        return UINT16_MAX;
}

static int bridge_vlan_append_set_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *str = NULL;
        uint16_t pvid, begin = UINT16_MAX;
        bool untagged, pvid_is_untagged;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        pvid = link_get_pvid(link, &pvid_is_untagged);

        for (uint16_t k = 0; k < BRIDGE_VLAN_BITMAP_MAX; k++) {

                if (k == pvid) {
                        /* PVID needs to be sent alone. Finish previous bits. */
                        if (begin != UINT16_MAX) {
                                assert(begin < k);

                                r = add_range(m, begin, k - 1, untagged, &str);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        r = add_single(m, pvid, pvid_is_untagged, /* is_pvid = */ true, &str);
                        if (r < 0)
                                return r;

                        continue;
                }

                if (!is_bit_set(k, link->network->bridge_vlan_bitmap)) {
                        /* This bit is not set. Finish previous bits. */
                        if (begin != UINT16_MAX) {
                                assert(begin < k);

                                r = add_range(m, begin, k - 1, untagged, &str);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        continue;
                }

                if (begin != UINT16_MAX) {
                        bool u;

                        assert(begin < k);

                        u = is_bit_set(k, link->network->bridge_vlan_untagged_bitmap);
                        if (untagged == u)
                                continue;

                        /* Tagging flag is changed from the previous bits. Finish them. */
                        r = add_range(m, begin, k - 1, untagged, &str);
                        if (r < 0)
                                return r;

                        begin = k;
                        untagged = u;
                        continue;
                }

                /* This is the starting point of a new bit sequence. Save the position and the tagging flag. */
                begin = k;
                untagged = is_bit_set(k, link->network->bridge_vlan_untagged_bitmap);
        }

        /* No pending bit sequence.
         * Why? There is a trick. The conf parsers below only accepts vlan ID in the range 0…4094, but in
         * the above loop, we run 0…4095. */
        assert_cc(BRIDGE_VLAN_BITMAP_MAX > VLANID_MAX);
        assert(begin == UINT16_MAX);

        log_link_debug(link, "Setting Bridge VLAN IDs: %s", strna(str));
        return 0;
}

static int bridge_vlan_append_del_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *str = NULL;
        uint16_t pvid, begin = UINT16_MAX;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        pvid = link_get_pvid(link, NULL);

        for (uint16_t k = 0; k < BRIDGE_VLAN_BITMAP_MAX; k++) {

                if (k == pvid ||
                    !is_bit_set(k, link->bridge_vlan_bitmap) ||
                    is_bit_set(k, link->network->bridge_vlan_bitmap)) {
                        /* This bit is not necessary to be removed. Finish previous bits. */
                        if (begin != UINT16_MAX) {
                                assert(begin < k);

                                r = add_range(m, begin, k - 1, /* untagged = */ false, &str);
                                if (r < 0)
                                        return r;

                                begin = UINT16_MAX;
                        }

                        continue;
                }

                if (begin != UINT16_MAX)
                        continue;

                /* This is the starting point of a new bit sequence. Save the position. */
                begin = k;
        }

        /* No pending bit sequence. */
        assert(begin == UINT16_MAX);

        log_link_debug(link, "Removing Bridge VLAN IDs: %s", strna(str));
        return 0;
}

static int bridge_vlan_append_set_tunnel_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *add_str = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        /* Process configured entries that are not yet applied */
        for (size_t i = 0; i < link->network->bridge_vlan_tunnel_vni.n_entries; i++) {
                BridgeVLANTunnelEntry *entry = &link->network->bridge_vlan_tunnel_vni.entries[i];

                /* Skip if already configured in the kernel */
                if (entry->is_configured)
                        continue;

                /* Open IFLA_BRIDGE_VLAN_TUNNEL_INFO container for this entry */
                r = sd_netlink_message_open_container(m, IFLA_BRIDGE_VLAN_TUNNEL_INFO);
                if (r < 0)
                        return r;

                if (entry->vid_start == entry->vid_end) {
                        /* Single VLAN */
                        r = add_tunnel_info(m, entry->vid_start, entry->vni_start, 0, &add_str);
                } else {
                        /* VLAN range */
                        r = add_tunnel_info(m, entry->vid_start, entry->vni_start, BRIDGE_VLAN_INFO_RANGE_BEGIN, &add_str);
                        if (r < 0)
                                goto close_container;

                        r = add_tunnel_info(m, entry->vid_end, entry->vni_end, BRIDGE_VLAN_INFO_RANGE_END, &add_str);
                }

                if (r < 0)
                        goto close_container;

                /* Close IFLA_BRIDGE_VLAN_TUNNEL_INFO container for this entry */
                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return r;

                continue;

close_container:
                sd_netlink_message_close_container(m);
                return r;
        }

        if (add_str)
                log_link_debug(link, "Setting Bridge VLAN Tunnel VNI: %s", add_str);

        return 0;
}

static int bridge_vlan_append_del_tunnel_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ char *del_str = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(m);

        /* Delete entries that exist in kernel but not in configuration */
        for (size_t i = 0; i < link->bridge_vlan_tunnel_existing.n_entries; i++) {
                BridgeVLANTunnelEntry *existing = &link->bridge_vlan_tunnel_existing.entries[i];

                /* Check if this entry is in the configured set */
                for (size_t j = 0; j < link->network->bridge_vlan_tunnel_vni.n_entries; j++) {
                        BridgeVLANTunnelEntry *configured = &link->network->bridge_vlan_tunnel_vni.entries[j];
                        if (configured->vid_start == existing->vid_start &&
                            configured->vid_end == existing->vid_end &&
                            configured->vni_start == existing->vni_start &&
                            configured->vni_end == existing->vni_end)
                                goto next_existing;
                }

                /* Not in config, mark for deletion */
                r = sd_netlink_message_open_container(m, IFLA_BRIDGE_VLAN_TUNNEL_INFO);
                if (r < 0)
                        return r;

                if (existing->vid_start == existing->vid_end) {
                        /* Single VLAN deletion */
                        r = add_tunnel_info(m, existing->vid_start, 0, 0, &del_str);
                } else {
                        /* VLAN range deletion */
                        r = add_tunnel_info(m, existing->vid_start, 0, BRIDGE_VLAN_INFO_RANGE_BEGIN, &del_str);
                        if (r < 0)
                                goto close_container;

                        r = add_tunnel_info(m, existing->vid_end, 0, BRIDGE_VLAN_INFO_RANGE_END, &del_str);
                }

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
                log_link_debug(link, "Deleting Bridge VLAN Tunnel VNI: %s", del_str);

        return 0;
}


int bridge_vlan_set_tunnel_message(Link *link, sd_netlink_message *m, bool is_set) {
        int r;

        assert(link);
        assert(m);

        /* Check if we have TunnelVNI entries */
        if (!link->network->bridge_vlan_tunnel_vni.entries || link->network->bridge_vlan_tunnel_vni.n_entries == 0)
                return 0;

        r = sd_rtnl_message_link_set_family(m, AF_BRIDGE);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, IFLA_AF_SPEC);
        if (r < 0)
                return r;

        if (is_set)
                r = bridge_vlan_append_set_tunnel_info(link, m);
        else
                r = bridge_vlan_append_del_tunnel_info(link, m);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

int bridge_vlan_set_message(Link *link, sd_netlink_message *m, bool is_set) {
        int r;

        assert(link);
        assert(m);

        r = sd_rtnl_message_link_set_family(m, AF_BRIDGE);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, IFLA_AF_SPEC);
        if (r < 0)
                return r;

        if (link->master_ifindex <= 0 || streq_ptr(link->kind, "bridge")) {
                /* If the setting is requested in a .network file for a bridge master (or a physical master)
                 * interface, then BRIDGE_FLAGS_SELF flag needs to be set. */
                r = sd_netlink_message_append_u16(m, IFLA_BRIDGE_FLAGS, BRIDGE_FLAGS_SELF);
                if (r < 0)
                        return r;
        }

        if (is_set)
                r = bridge_vlan_append_set_info(link, m);
        else
                r = bridge_vlan_append_del_info(link, m);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

int link_update_bridge_vlan(Link *link, sd_netlink_message *m) {
        _cleanup_free_ void *data = NULL;
        size_t len;
        uint16_t begin = UINT16_MAX;
        int r, family;

        assert(link);
        assert(m);

        r = sd_rtnl_message_get_family(m, &family);
        if (r < 0)
                return r;

        if (family != AF_BRIDGE)
                return 0;

        r = sd_netlink_message_read_data(m, IFLA_AF_SPEC, &len, &data);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        memzero(link->bridge_vlan_bitmap, sizeof(link->bridge_vlan_bitmap));

        for (struct rtattr *rta = data; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                struct bridge_vlan_info *p;

                if (RTA_TYPE(rta) != IFLA_BRIDGE_VLAN_INFO)
                        continue;
                if (RTA_PAYLOAD(rta) != sizeof(struct bridge_vlan_info))
                        continue;

                p = RTA_DATA(rta);

                if (FLAGS_SET(p->flags, BRIDGE_VLAN_INFO_RANGE_BEGIN)) {
                        begin = p->vid;
                        continue;
                }

                if (FLAGS_SET(p->flags, BRIDGE_VLAN_INFO_RANGE_END)) {
                        for (uint16_t k = begin; k <= p->vid; k++)
                                set_bit(k, link->bridge_vlan_bitmap);

                        begin = UINT16_MAX;
                        continue;
                }

                if (FLAGS_SET(p->flags, BRIDGE_VLAN_INFO_PVID)) {
                        link->bridge_vlan_pvid = p->vid;
                        link->bridge_vlan_pvid_is_untagged = FLAGS_SET(p->flags, BRIDGE_VLAN_INFO_UNTAGGED);
                }

                set_bit(p->vid, link->bridge_vlan_bitmap);
                begin = UINT16_MAX;
        }

        return 0;
}

int link_update_bridge_vlan_tunnel_info(Link *link, sd_netlink_message *m) {
        _cleanup_free_ void *data = NULL;
        _cleanup_free_ BridgeVLANTunnelEntry *existing_entries = NULL;
        size_t len, n_existing = 0;
        int r, family;

        assert(link);
        assert(m);

        r = sd_rtnl_message_get_family(m, &family);
        if (r < 0)
                return r;

        if (family != AF_BRIDGE)
                return 0;

        r = sd_netlink_message_read_data(m, IFLA_AF_SPEC, &len, &data);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        /* Parse tunnel info from IFLA_AF_SPEC */
        for (struct rtattr *rta = data; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                uint16_t vid = UINT16_MAX, vid_end = UINT16_MAX;
                uint32_t vni = 0, vni_end = 0;
                size_t attr_len;

                if (RTA_TYPE(rta) != IFLA_BRIDGE_VLAN_TUNNEL_INFO)
                        continue;

                attr_len = RTA_PAYLOAD(rta);
                for (struct rtattr *attr = RTA_DATA(rta);
                     RTA_OK(attr, attr_len);
                     attr = RTA_NEXT(attr, attr_len)) {

                        switch (RTA_TYPE(attr)) {
                        case IFLA_BRIDGE_VLAN_TUNNEL_VID:
                                if (RTA_PAYLOAD(attr) != sizeof(uint16_t))
                                        break;
                                if (vid == UINT16_MAX)
                                        vid = *(uint16_t *) RTA_DATA(attr);
                                else
                                        vid_end = *(uint16_t *) RTA_DATA(attr);
                                break;
                        case IFLA_BRIDGE_VLAN_TUNNEL_ID:
                                if (RTA_PAYLOAD(attr) != sizeof(uint32_t))
                                        break;
                                if (vni == 0)
                                        vni = *(uint32_t *) RTA_DATA(attr);
                                else
                                        vni_end = *(uint32_t *) RTA_DATA(attr);
                                break;
                        }
                }

                /* Add to existing entries if valid (vni != 0, not marked for deletion) */
                if (vid != UINT16_MAX && vni != 0) {
                        BridgeVLANTunnelEntry *new_entries = reallocarray(
                                existing_entries,
                                n_existing + 1,
                                sizeof(BridgeVLANTunnelEntry));
                        if (!new_entries)
                                return log_oom();

                        existing_entries = new_entries;
                        new_entries[n_existing] = (BridgeVLANTunnelEntry) {
                                .vid_start = vid,
                                .vid_end = vid_end != UINT16_MAX ? vid_end : vid,
                                .vni_start = vni,
                                .vni_end = vni_end != 0 ? vni_end : vni,
                                .is_configured = false,
                        };
                        n_existing++;
                }
        }

        /* Update is_configured flag for entries that match the configuration */
        for (size_t i = 0; i < link->network->bridge_vlan_tunnel_vni.n_entries; i++) {
                BridgeVLANTunnelEntry *configured = &link->network->bridge_vlan_tunnel_vni.entries[i];

                for (size_t j = 0; j < n_existing; j++) {
                        BridgeVLANTunnelEntry *existing = &existing_entries[j];
                        if (existing->vid_start == configured->vid_start &&
                            existing->vid_end == configured->vid_end &&
                            existing->vni_start == configured->vni_start &&
                            existing->vni_end == configured->vni_end) {
                                configured->is_configured = true;
                                break;
                        }
                }
        }

        /* Copy back to link struct for future use */
        link->bridge_vlan_tunnel_existing.entries = mfree(link->bridge_vlan_tunnel_existing.entries);
        link->bridge_vlan_tunnel_existing.entries = existing_entries;
        link->bridge_vlan_tunnel_existing.n_entries = n_existing;
        existing_entries = NULL;

        return 0;
}

void network_adjust_bridge_vlan(Network *network) {
        assert(network);

        for (uint16_t k = 0; k < BRIDGE_VLAN_BITMAP_MAX; k++)
                if (is_bit_set(k, network->bridge_vlan_untagged_bitmap))
                        set_bit(k, network->bridge_vlan_bitmap);

        if (vlanid_is_valid(network->bridge_vlan_pvid))
                set_bit(network->bridge_vlan_pvid, network->bridge_vlan_bitmap);
}

int config_parse_bridge_vlan_id(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint16_t v, *id = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *id = BRIDGE_VLAN_KEEP_PVID;
                return 0;
        }

        if (parse_boolean(rvalue) == 0) {
                *id = BRIDGE_VLAN_REMOVE_PVID;
                return 0;
        }

        r = parse_vlanid(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        *id = v;
        return 0;
}

int config_parse_bridge_vlan_id_range(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        uint32_t *bitmap = data;
        uint16_t vid, vid_end;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                memzero(bitmap, BRIDGE_VLAN_BITMAP_LEN * sizeof(uint32_t));
                return 0;
        }

        r = parse_vid_range(rvalue, &vid, &vid_end);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        /* Track the VLAN range for TunnelVNI */
        network->bridge_vlan_section_start = vid;
        network->bridge_vlan_section_end = vid_end;

        for (; vid <= vid_end; vid++)
                set_bit(vid, bitmap);

        return 0;
}

void bridge_vlan_mark_tunnel_vni_configured(Link *link) {
        assert(link);
        assert(link->network);

        /* Mark all tunnel VNI entries as configured after successful Netlink operation */
        for (size_t i = 0; i < link->network->bridge_vlan_tunnel_vni.n_entries; i++) {
                BridgeVLANTunnelEntry *entry = &link->network->bridge_vlan_tunnel_vni.entries[i];
                entry->is_configured = true;
        }
}

int config_parse_bridge_vlan_tunnel_vni(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        uint32_t vni, vni_end;
        char *dash;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue))
                return 0;

        /* Parse VNI range: "10001" or "10001-10005" */
        dash = strchr(rvalue, '-');
        if (dash) {
                _cleanup_free_ char *vni_str = NULL;
                vni_str = strndup(rvalue, dash - rvalue);
                if (!vni_str)
                        return log_oom();

                r = safe_atou32(vni_str, &vni);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse VNI start value, ignoring: %s",
                                   vni_str);
                        return 0;
                }

                r = safe_atou32(dash + 1, &vni_end);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse VNI end value, ignoring: %s",
                                   dash + 1);
                        return 0;
                }
        } else {
                r = safe_atou32(rvalue, &vni);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse VNI, ignoring: %s",
                                   rvalue);
                        return 0;
                }
                vni_end = vni;
        }

        /* Validate VNI range (24-bit) */
        if (vni > VXLAN_VID_MAX || vni_end > VXLAN_VID_MAX || vni > vni_end) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid VNI range, ignoring: %s",
                           rvalue);
                return 0;
        }

        /* Add entry to tunnel VNI array */
        BridgeVLANTunnelEntry *new_entries = reallocarray(
                network->bridge_vlan_tunnel_vni.entries,
                network->bridge_vlan_tunnel_vni.n_entries + 1,
                sizeof(BridgeVLANTunnelEntry));
        if (!new_entries)
                return log_oom();

        network->bridge_vlan_tunnel_vni.entries = new_entries;
        new_entries[network->bridge_vlan_tunnel_vni.n_entries] = (BridgeVLANTunnelEntry) {
                .vid_start = network->bridge_vlan_section_start,
                .vid_end = network->bridge_vlan_section_end,
                .vni_start = vni,
                .vni_end = vni_end,
                .is_configured = false,
        };
        network->bridge_vlan_tunnel_vni.n_entries++;

        return 0;
}
