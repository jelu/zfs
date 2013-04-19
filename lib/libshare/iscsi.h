/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Gunnar Beutner
 */

#define PROC_IET_VOLUME "/proc/net/iet/volume"
#define IETM_CMD_PATH "/usr/sbin/ietadm"
#define DOMAINNAME_FILE "/etc/domainname"
#define TARGET_NAME_FILE "/etc/iscsi_target_id"
#define EXTRA_SHARE_SCRIPT "/sbin/zfs_share_iscsi"

/**
 * tid:1 name:iqn.2012-11.com.bayour:share.VirtualMachines.Ubuntu.Maverick.Desktop
 *	lun:0 state:0 iotype:fileio iomode:wt blocks:31457280 blocksize:512 \
 *	path:/dev/zvol/share/VirtualMachines/Ubuntu/Maverick/Desktop
 */
typedef struct iscsi_shareopts_s {
	char	name[255];	/* Target IQN name */
	int	lun;		/* LUN number */
	char	type[10];	/* disk or tape */
	char	iomode[3];	/* wb, ro or wt */
	int	blocksize;	/* 512, 1024, 2048 or 4096 */
} iscsi_shareopts_t;

typedef struct iscsi_target_s {
        int     tid;            /* Target ID */
        char    name[255];      /* Target Name */
        int     lun;            /* Target LUN */
        int     state;          /* Target State */
        char    iotype[3];      /* Target IO Type */
        char    iomode[20];     /* Target IO Mode */
        int     blocks;         /* Target Size (blocks) */
        int     blocksize;      /* Target Block Size (bytes) */
        char    path[PATH_MAX];	/* Target Path */

        struct iscsi_target_s *next;
} iscsi_target_t;

iscsi_target_t *iscsi_targets;

void libshare_iscsi_init(void);
int iscsi_disable_share_all(void);
