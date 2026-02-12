/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2024 systemd Project. All rights reserved.
***/

#include "networkd-forward.h"

typedef struct {
        uint32_t vni_start;
        uint32_t vni_end;
} VXLANVNIFilterEntry;

typedef struct {
        VXLANVNIFilterEntry *entries;
        size_t n_entries;
} VXLANVNIFilter;

int bridge_vni_set_vnientry_message(Link *link, sd_netlink_message *m, bool is_set);
