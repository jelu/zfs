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
 * Copyright (c) 2011,2012 Turbo Fredriksson <turbo@bayour.com>, based on nfs.c
 *                         by Gunnar Beutner
 *
 * This is an addition to the zfs device driver to retrieve, add and remove
 * iSCSI targets using the 'ietadm' command. As of this, it only currently
 * supports the IET iSCSI target implementation.
 *
 * It uses a linked list named 'iscsi_target_t' to keep track of all targets.
 *
 * It will call ietadm to both add or remove a iSCSI
 * target from the call to 'zfs share':
 * 
 *        zfs create -V tank/test
 *        zfs set shareiscsi=on tank/test
 *        zfs share tank/test
 * 
 * The driver will execute the following commands (example!):
 * 
 *   /usr/sbin/ietadm --op new --tid 1 --params 
 *	Name=iqn.2012-01.com.bayour:tank.test1
 *   /usr/sbin/ietadm --op new --tid 1 --lun 0 --params 
 *	Path=/dev/zvol/tank/test,Type=fileio
 * 
 * It (the driver) will automatically calculate the TID and IQN and use only
 * the ZVOL (in this case 'tank/test') in the command lines.
 */

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <libzfs.h>
#include <libshare.h>
#include <sys/fs/zfs.h>
#include "libshare_impl.h"
#include "iscsi.h"

static boolean_t iscsi_available(void);

static sa_fstype_t *iscsi_fstype;

/**
 * What iSCSI implementation found
 * -1: none
 *  1: IET found
 *  2: SCST found
 */
static int iscsi_implementation;

typedef struct iscsi_dirs_s {
	char		path[PATH_MAX];
	char		entry[PATH_MAX];
	struct stat	stats;

	struct	iscsi_dirs_s *next;
} iscsi_dirs_t;

static iscsi_dirs_t *
iscsi_look_for_stuff(char *path, const char *needle, boolean_t check_dir, int index)
{
	char path2[PATH_MAX], path3[PATH_MAX];
	DIR *dir;
	struct dirent *directory;
	struct stat eStat;
	iscsi_dirs_t *entries = NULL, *new_entries = NULL;

	if ((dir = opendir(path))) {
		while ((directory = readdir(dir))) {
			if (directory->d_name[0] == '.')
				continue;

			snprintf(path2, sizeof (path2),
				 "%s/%s", path, directory->d_name);

			if (stat(path2, &eStat) == -1)
				goto look_out;

			if (check_dir && !S_ISDIR(eStat.st_mode))
				continue;

			if (needle != NULL) {
				if (index) {
					if (strncmp(directory->d_name, needle, index) == 0)
						strncpy(path3, path2, sizeof(path3));
				} else {
					if (strcmp(directory->d_name, needle) == 0)
						strncpy(path3, path2, sizeof(path3));
				}
			} else {
				if (strcmp(directory->d_name, "mgmt") == 0) 
					continue;

				strncpy(path3, path2, sizeof(path3));
			}

			entries = (iscsi_dirs_t *)malloc(sizeof (iscsi_dirs_t));
			if (entries == NULL)
				goto look_out;

			strncpy(entries->path, path3, sizeof(entries->path));
			strncpy(entries->entry, directory->d_name, sizeof(entries->entry));
			entries->stats = eStat;

			entries->next = new_entries;
			new_entries = entries;
		}

look_out:
		closedir(dir);
	}

	return new_entries;
}

static int
iscsi_read_sysfs_value(char *path, char **value)
{
	int rc = SA_SYSTEM_ERR;
	char buffer[255];
	FILE *scst_sysfs_file_fp = NULL;

	*value = NULL;

	scst_sysfs_file_fp = fopen(path, "r");
	if (scst_sysfs_file_fp != NULL) {
		if (fgets(buffer, sizeof (buffer), scst_sysfs_file_fp) != NULL) {
			buffer[strlen(buffer)-1] = '\0';

			*value = strdup(buffer);

			rc = SA_OK;
		}

		fclose(scst_sysfs_file_fp);
	}

	return rc;
}

static int
iscsi_write_sysfs_value(char *path, char *value)
{
	char full_path[PATH_MAX];
	int rc = SA_SYSTEM_ERR;
	FILE *scst_sysfs_file_fp = NULL;

	sprintf(full_path, "%s/%s", SYSFS_SCST, path);

#ifdef DEBUG
	fprintf(stderr, "iscsi_write_sysfs_value: %s\n                         => %s\n",
		full_path, value);
	rc = SA_OK;
#endif

	scst_sysfs_file_fp = fopen(full_path, "w");
	if (scst_sysfs_file_fp != NULL) {
		if (fputs(value, scst_sysfs_file_fp))
			rc = SA_OK;

		fclose(scst_sysfs_file_fp);
	}

	return rc;
}

/*
 * Generate a target name using the current year and month,
 * the domain name and the path.
 *
 * OR: Use information from /etc/iscsi_target_id:
 *     Example: iqn.2012-11.com.bayour
 *
 * => iqn.yyyy-mm.tld.domain:path
 */
static int
iscsi_generate_target(const char *path, char *iqn, size_t iqn_len)
{
	char tsbuf[8]; /* YYYY-MM */
	char domain[256], revname[255], name[255],
		tmpdom[255], *p, tmp[20][255], *pos,
		buffer[512], file_iqn[255];
	time_t now;
	struct tm *now_local;
	int i;
	FILE *domainname_fp = NULL, *iscsi_target_name_fp = NULL;

	if (path == NULL)
		return SA_SYSTEM_ERR;

	iscsi_target_name_fp = fopen(TARGET_NAME_FILE, "r");
	if (iscsi_target_name_fp == NULL) {
		/* Generate a name using domain name and date etc */

		/* Get current time in EPOCH */
		now = time(NULL);
		now_local = localtime(&now);
		if (now_local == NULL)
			return -1;

		/* Parse EPOCH and get YYY-MM */
		if (strftime(tsbuf, sizeof (tsbuf), "%Y-%m", now_local) == 0)
			return -1;

#ifdef HAVE_GETDOMAINNAME
		/* Retrieve the domain */
		if (getdomainname(domain, sizeof (domain)) < 0) {
			/* Could not get domain via getdomainname() */
#endif
			domainname_fp = fopen(DOMAINNAME_FILE, "r");
			if (domainname_fp == NULL) {
				fprintf(stderr, "ERROR: Can't open %s: %s\n",
					DOMAINNAME_FILE, strerror(errno));
				return SA_SYSTEM_ERR;
			}

			if (fgets(buffer, sizeof (buffer), domainname_fp) != NULL) {
				strncpy(domain, buffer, sizeof (domain)-1);
				domain[strlen(domain)-1] = '\0';
			} else
				return SA_SYSTEM_ERR;

			fclose(domainname_fp);
#ifdef HAVE_GETDOMAINNAME
		}
#endif

		/* Tripple check that we really have a domainname! */
		if ((strlen(domain) == 0) || (strcmp(domain, "(none)") == 0)) {
			fprintf(stderr, "ERROR: Can't retreive domainname!\n");
			return SA_SYSTEM_ERR;
		}

		/* Reverse the domainname ('bayour.com' => 'com.bayour') */
		strncpy(tmpdom, domain, sizeof (domain));

		i = 0;
		p = strtok(tmpdom, ".");
		while (p != NULL) {
			strncpy(tmp[i], p, strlen(p));
			p = strtok(NULL, ".");
			
			i++;
		}
		i--;
		memset(&revname[0], 0, sizeof (revname));
		for (; i >= 0; i--) {
			if (strlen(revname)) {
				snprintf(tmpdom, strlen(revname)+strlen(tmp[i])+2,
					 "%s.%s", revname, tmp[i]);
				snprintf(revname, strlen(tmpdom)+1, "%s", tmpdom);
			} else {
				strncpy(revname, tmp[i], strlen(tmp[i]));
				revname [sizeof(revname)-1] = '\0';
			}
		}
	} else {
		/* Use the content of file as the IQN => "iqn.2012-11.com.bayour" */
		if (fgets(buffer, sizeof (buffer), iscsi_target_name_fp) != NULL) {
			strncpy(file_iqn, buffer, sizeof (file_iqn)-1);
			file_iqn[strlen(file_iqn)-1] = '\0';
		} else
			return SA_SYSTEM_ERR;

		fclose(iscsi_target_name_fp);
	}

	/* Take the dataset name, replace / with . */
	strncpy(name, path, sizeof(name));
	pos = name;
	while (*pos != '\0') {
		switch( *pos ) {
		case '/':
		case '-':
		case ':':
		case ' ':
			*pos = '.';
		}
		++pos;
	}

	/* Put the whole thing togheter => "iqn.2012-11.com.bayour:share.VirtualMachines.Astrix" */
	if (strlen(file_iqn))
		snprintf(iqn, iqn_len, "%s:%s", file_iqn, name);
	else
		snprintf(iqn, iqn_len, "iqn.%s.%s:%s", tsbuf, revname, name);

	return SA_OK;
}

static void
iscsi_generate_device_name(char *name, char **device)
{
	int i;
	char string[17], src_chars[62] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	/* Seed number for rand() */
	srand((unsigned int) time(0) + getpid());

	/* ASCII characters only */
	for (i = 0; i < 16; ++i)
		string[i] = src_chars[ rand() % 62];
	string[i] = '\0';

	*device = strdup(string);
}

/* Reads the file and register if a tid have a sid. Save the value in iscsi_targets->state */
static iscsi_session_t *
iscsi_retrieve_sessions_iet(void)
{
	FILE *iscsi_volumes_fp = NULL;
	char buffer[512];
	char *line, *token, *key, *value, *colon, *dup_value;
	int buffer_len, rc = SA_OK;
	iscsi_session_t *session, *new_session = NULL;
	enum { ISCSI_SESSION, ISCSI_SID, ISCSI_CID } type;

	/* For storing the share info */
	char *tid = NULL, *name = NULL, *sid = NULL, *initiator = NULL, *cid = NULL,
		*ip = NULL, *state = NULL, *hd = NULL, *dd = NULL;

	/* Open file with targets */
	iscsi_volumes_fp = fopen(PROC_IET_SESSION, "r");
	if (iscsi_volumes_fp == NULL) {
		rc = SA_SYSTEM_ERR;
		goto retrieve_sessions_iet_out;
	}

	/* Load the file... */
	while (fgets(buffer, sizeof (buffer), iscsi_volumes_fp) != NULL) {
		/* Trim trailing new-line character(s). */
		buffer_len = strlen(buffer);
		while (buffer[buffer_len - 1] == '\r' ||
		       buffer[buffer_len - 1] == '\n')
			buffer[buffer_len - 1] = '\0';

		if (buffer[0] != '\t') {
			/*
			 * Line doesn't start with a TAB which means this is a
			 * session definition
			 */
			line = buffer;
			type = ISCSI_SESSION;

			free(tid);
			tid = NULL;

			free(name);
			name = NULL;
		} else if (buffer[0] == '\t' && buffer[1] == '\t') {
			/* Start with two tabs - CID definition */
			line = buffer + 2;
			type = ISCSI_CID;

			free(cid);
			cid = NULL;

			free(ip);
			ip = NULL;

			free(state);
			state = NULL;

			free(hd);
			hd = NULL;

			free(dd);
			dd = NULL;
		} else {
			/* Start with one tab - SID definition */
			line = buffer + 1;
			type = ISCSI_SID;

			free(sid);
			sid = NULL;

			free(initiator);
			initiator = NULL;
		}

		/* Get each option, which is separated by space */
		/* token='tid:18' */
		token = strtok(line, " ");
		while (token != NULL) {
			colon = strchr(token, ':');

			if (colon == NULL)
				goto next_sessions;

			key = token;
			value = colon + 1;
			*colon = '\0';

			dup_value = strdup(value);

			if (dup_value == NULL) {
				rc = SA_NO_MEMORY;
				goto retrieve_sessions_iet_out;
			}

			if (type == ISCSI_SESSION) {
				if (strcmp(key, "tid") == 0)
					tid = dup_value;
				else if (strcmp(key, "name") == 0)
					name = dup_value;
				else
					free(dup_value);
			} else if (type == ISCSI_SID) {
				if (strcmp(key, "sid") == 0)
					sid = dup_value;
				else if (strcmp(key, "initiator") == 0)
					initiator = dup_value;
				else
					free(dup_value);
			} else {
				if (strcmp(key, "cid") == 0)
					cid = dup_value;
				else if (strcmp(key, "ip") == 0)
					ip = dup_value;
				else if (strcmp(key, "state") == 0)
					state = dup_value;
				else if (strcmp(key, "hd") == 0)
					hd = dup_value;
				else if (strcmp(key, "dd") == 0)
					dd = dup_value;
				else
					free(dup_value);
			}

next_sessions:
			token = strtok(NULL, " ");
		}

		if (tid == NULL || sid == NULL || cid == NULL || name == NULL ||
		    initiator == NULL || ip == NULL || state == NULL || dd == NULL ||
		    hd == NULL)
			continue; /* Incomplete session definition */

		session = (iscsi_session_t *)malloc(sizeof (iscsi_session_t));
		if (session == NULL) {
			rc = SA_NO_MEMORY;
			goto retrieve_sessions_iet_out;
		}

		/* Save the values in the struct */
		session->tid = atoi(tid);
		session->sid = atoi(sid);
		session->cid = atoi(cid);

		strncpy(session->name, name, sizeof (session->name));
		strncpy(session->initiator, initiator, sizeof (session->initiator));
		strncpy(session->ip, ip, sizeof (session->ip));
		strncpy(session->hd, hd, sizeof (session->hd));
		strncpy(session->dd, dd, sizeof (session->dd));

		if (strcmp(state, "active") == 0)
			session->state = 1;
		else
			session->state = 0;

#ifdef DEBUG
		fprintf(stderr, "iscsi_retrieve_sessions: target=%s, tid=%d, "
			"sid=%d, cid=%d, initiator=%s, ip=%s, state=%d\n",
			session->name, session->tid, session->sid, session->cid,
			session->initiator, session->ip, session->state);
#endif

		/* Append the sessions to the list of new sessions */
		session->next = new_session;
		new_session = session;
	}

retrieve_sessions_iet_out:
	if (iscsi_volumes_fp != NULL)
		fclose(iscsi_volumes_fp);

	return new_session;
}

/* iscsi_retrieve_targets_iet() retrieves list of iSCSI targets - IET version */
static int
iscsi_retrieve_targets_iet(void)
{
	FILE *iscsi_volumes_fp = NULL;
	char buffer[512];
	char *line, *token, *key, *value, *colon, *dup_value;
	char *tid = NULL, *name = NULL, *lun = NULL, *state = NULL;
	char *iotype = NULL, *iomode = NULL, *blocks = NULL;
	char *blocksize = NULL, *path = NULL;
	iscsi_target_t *target, *new_targets = NULL;
	iscsi_session_t *session, *sessions;
	int buffer_len, rc = SA_OK;
	enum { ISCSI_TARGET, ISCSI_LUN } type;

	/* Get all sessions */
	sessions = iscsi_retrieve_sessions_iet();

	/* Open file with targets */
	iscsi_volumes_fp = fopen(PROC_IET_VOLUME, "r");
	if (iscsi_volumes_fp == NULL) {
		rc = SA_SYSTEM_ERR;
		goto retrieve_targets_iet_out;
	}

	/* Load the file... */
	while (fgets(buffer, sizeof (buffer), iscsi_volumes_fp) != NULL) {
		/* Trim trailing new-line character(s). */
		buffer_len = strlen(buffer);
		while (buffer[buffer_len - 1] == '\r' ||
		       buffer[buffer_len - 1] == '\n')
			buffer[buffer_len - 1] = '\0';

		if (buffer[0] != '\t') {
			/*
			 * Line doesn't start with a TAB which means this is a
			 * target definition
			 */
			line = buffer;
			type = ISCSI_TARGET;

			free(tid);
			tid = NULL;

			free(name);
			name = NULL;
		} else {
			/* LUN definition */
			line = buffer + 1;
			type = ISCSI_LUN;

			free(lun);
			lun = NULL;

			free(state);
			state = NULL;

			free(iotype);
			iotype = NULL;

			free(iomode);
			iomode = NULL;

			free(blocks);
			blocks = NULL;

			free(blocksize);
			blocksize = NULL;

			free(path);
			path = NULL;
		}

		/* Get each option, which is separated by space */
		/* token='tid:18' */
		token = strtok(line, " ");
		while (token != NULL) {
			colon = strchr(token, ':');

			if (colon == NULL)
				goto next_targets;

			key = token;
			value = colon + 1;
			*colon = '\0';

			dup_value = strdup(value);

			if (dup_value == NULL) {
				rc = SA_NO_MEMORY;
				goto retrieve_targets_iet_out;
			}

			if (type == ISCSI_TARGET) {
				if (strcmp(key, "tid") == 0)
					tid = dup_value;
				else if (strcmp(key, "name") == 0)
					name = dup_value;
				else
					free(dup_value);
			} else {
				if (strcmp(key, "lun") == 0)
					lun = dup_value;
				else if (strcmp(key, "state") == 0)
					state = dup_value;
				else if (strcmp(key, "iotype") == 0)
					iotype = dup_value;
				else if (strcmp(key, "iomode") == 0)
					iomode = dup_value;
				else if (strcmp(key, "blocks") == 0)
					blocks = dup_value;
				else if (strcmp(key, "blocksize") == 0)
					blocksize = dup_value;
				else if (strcmp(key, "path") == 0)
					path = dup_value;
				else
					free(dup_value);
			}

next_targets:
			token = strtok(NULL, " ");
		}

		if (type != ISCSI_LUN)
			continue;

		if (tid == NULL || name == NULL || lun == NULL ||
		    state == NULL || iotype == NULL || iomode == NULL ||
		    blocks == NULL || blocksize == NULL || path == NULL)
			continue; /* Incomplete LUN definition */

		target = (iscsi_target_t *)malloc(sizeof (iscsi_target_t));
		if (target == NULL) {
			rc = SA_NO_MEMORY;
			goto retrieve_targets_iet_out;
		}

		target->tid = atoi(tid);
		strncpy(target->name, name, sizeof (target->name));
		target->lun = atoi(lun);
		target->state = atoi(state);
		strncpy(target->iotype, iotype, sizeof (target->iotype));
		strncpy(target->iomode, iomode, sizeof (target->iomode));
		target->blocks = atoi(blocks);
		target->blocksize = atoi(blocksize);
		strncpy(target->path, path, sizeof (target->path));

		/* Link the session here */
		target->session = NULL;
		session = sessions;
		while (session != NULL) {
			if (session->tid == target->tid) {
				target->session = session;

				break;
			}

			session = session->next;
		}

#ifdef DEBUG
		fprintf(stderr, "iscsi_retrieve_targets: target=%s, tid=%d, path=%s, active=%d\n",
			target->name, target->tid, target->path,
			target->session ? target->session->state : -1);
#endif

		/* Append the target to the list of new targets */
		target->next = new_targets;
		new_targets = target;
	}

	/* TODO: free existing iscsi_targets */
	iscsi_targets = new_targets;

retrieve_targets_iet_out:
	if (iscsi_volumes_fp != NULL)
		fclose(iscsi_volumes_fp);

	free(tid);
	free(name);
	free(lun);
	free(state);
	free(iotype);
	free(iomode);
	free(blocks);
	free(blocksize);
	free(path);

	return rc;
}

/* iscsi_retrieve_targets_scst() retrieves list of iSCSI targets - SCST version */
static int
iscsi_retrieve_targets_scst(void)
{
	char *buffer, *link = NULL, *dup_path, path[PATH_MAX], tmp_path[PATH_MAX];
	int rc = SA_OK;
	iscsi_dirs_t *entries1, *entries2, *entries3;
	iscsi_target_t *target, *new_targets = NULL;

	/* For storing the share info */
	char *tid = NULL, *lun = NULL, *state = NULL, *blocksize = NULL;
	char *name = NULL, *iotype = NULL, *iomode = NULL, *dev_path = NULL,
		 *device = NULL;

	/* DIR: /sys/kernel/scst_tgt/targets */
	snprintf(path, strlen(SYSFS_SCST)+9, "%s/targets", SYSFS_SCST);
	entries1 = iscsi_look_for_stuff(path, "iscsi", B_TRUE, 0);
	while (entries1 != NULL) {
		entries2 = iscsi_look_for_stuff(entries1->path, "iqn.", B_TRUE, 4);
		while (entries2 != NULL) {
			/* DIR: /sys/kernel/scst_tgt/targets/iscsi/iqn.* */
			dup_path = entries2->path;

			/* Save the share name */
			name = strdup(entries2->entry);

			/* RETREIVE state */
			snprintf(tmp_path, strlen(dup_path)+9, "%s/enabled", dup_path);
			iscsi_read_sysfs_value(tmp_path, &buffer);
			state = strdup(buffer);

			/* RETREIVE tid */
			snprintf(tmp_path, strlen(dup_path)+5, "%s/tid", dup_path);
			iscsi_read_sysfs_value(tmp_path, &buffer);
			tid = strdup(buffer);

			/* RETREIVE lun(s) */
			snprintf(tmp_path, strlen(dup_path)+6,
				 "%s/luns", dup_path);
			entries3 = iscsi_look_for_stuff(tmp_path, NULL, B_TRUE, 0);
			while (entries3 != NULL) {
				lun = strdup(entries3->entry);

				/* RETREIVE blocksize */
				snprintf(tmp_path, strlen(dup_path)+25,
					 "%s/luns/%s/device/blocksize", dup_path, lun);
				iscsi_read_sysfs_value(tmp_path, &buffer);
				blocksize = strdup(buffer);

				/* RETREIVE block device path */
				snprintf(tmp_path, strlen(dup_path)+24,
					 "%s/luns/%s/device/filename", dup_path, lun);
				iscsi_read_sysfs_value(tmp_path, &buffer);
				dev_path = strdup(buffer);

				/* RETREIVE scst device name
				 * trickier: '6550a239-iscsi1' (s@.*-@@) */
				snprintf(tmp_path, strlen(dup_path)+26,
					 "%s/luns/%s/device/t10_dev_id", dup_path, lun);
				iscsi_read_sysfs_value(tmp_path, &buffer);
				device = strstr(buffer, "-")+1;

				/* RETREIVE iotype
				 * tricker: it's only availible in the link: */
				// $SYSFS/targets/iscsi/$name/luns/0/device/handler
				// => /sys/kernel/scst_tgt/handlers/vdisk_blockio
				snprintf(tmp_path, strlen(dup_path)+23,
					 "%s/luns/%s/device/handler", dup_path, lun);

				link = (char *) calloc(PATH_MAX, 1);
				if (link == NULL) {
					rc = SA_NO_MEMORY;
					goto retrieve_targets_scst_out;
				}

				readlink(tmp_path, link, PATH_MAX);
				link[strlen(link)] = '\0';
				iotype = strstr(link, "_") + 1;

				/* TODO: Retrieve iomode */


				target = (iscsi_target_t *)malloc(sizeof (iscsi_target_t));
				if (target == NULL) {
					rc = SA_NO_MEMORY;
					goto retrieve_targets_scst_out;
				}

				target->tid = atoi(tid);
				target->lun = atoi(lun);
				target->state = atoi(state);
				target->blocksize = atoi(blocksize);

				strncpy(target->name,   name,     strlen(name));
				strncpy(target->path,   dev_path, strlen(dev_path));
				strncpy(target->device, device,   strlen(device));
				strncpy(target->iotype, iotype,   strlen(iotype));
// TODO				strncpy(target->iomode, iomode,   strlen(iomode));

#ifdef DEBUG
				fprintf(stderr, "iscsi_retrieve_targets: target=%s, tid=%d, path=%s\n",
					target->name, target->tid, target->path);
#endif

				/* Append the target to the list of new targets */
				target->next = new_targets;
				new_targets = target;

				/* Next entry in lun directory */
				entries3 = entries3->next;
			}

			/* Next entry in target directory */
			entries2 = entries2->next;
		}

		/* Next target dir */
		entries1 = entries1->next;
	}

	/* TODO: free existing iscsi_targets */
	iscsi_targets = new_targets;

retrieve_targets_scst_out:
	return rc;
}

/* WRAPPER: Depending on iSCSI implementation, call the relevant function */
static int
iscsi_retrieve_targets(void)
{
	int rc = SA_OK;

	if (iscsi_implementation == 1)
		rc = iscsi_retrieve_targets_iet();
	else if (iscsi_implementation == 2)
		rc = iscsi_retrieve_targets_scst();

	return rc;
}

/**
 * Validates share option(s).
 */
static int
iscsi_get_shareopts_cb(const char *key, const char *value, void *cookie)
{
	char *dup_value;
	int lun;
	iscsi_shareopts_t *opts = (iscsi_shareopts_t *)cookie;

	if (strcmp(key, "on") == 0)
		return SA_OK;

	/* iqn is an alias to name */
	if (strcmp(key, "iqn") == 0)
		key = "name";

	/* iotype is what's used in PROC_IET_VOLUME, but Type in ietadm
	 * and 'type' in shareiscsi option...
	 */
	if (strcmp(key, "iotype") == 0 ||
	    strcmp(key, "Type") == 0)
		key = "type";

	/* Just for completeness */
	if (strcmp(key, "BlockSize") == 0)
		key = "blocksize";

	/* Verify all options */
	if (strcmp(key, "name") != 0 &&
	    strcmp(key, "lun") != 0 &&
	    strcmp(key, "type") != 0 &&
	    strcmp(key, "iomode") != 0 &&
	    strcmp(key, "blocksize") != 0)
		return SA_SYNTAX_ERR;


	dup_value = strdup(value);
	if (dup_value == NULL)
		return SA_NO_MEMORY;

	/* Get share option values */
	if (strcmp(key, "name") == 0) {
		strncpy(opts->name, dup_value, sizeof (opts->name));
		opts->name [sizeof(opts->name)-1] = '\0';
	}

	if (strcmp(key, "type") == 0) {
		/* Make sure it's a valid type value */
		if (strcmp(dup_value, "fileio") != 0 &&
		    strcmp(dup_value, "blockio") != 0 &&
		    strcmp(dup_value, "nullio") != 0 &&
		    strcmp(dup_value, "disk") != 0 &&
		    strcmp(dup_value, "tape") != 0)
			return SA_SYNTAX_ERR;

		/**
		 * The *Solaris options 'disk' (and future 'tape')
		 * isn't availible in ietadm. It _seems_ that 'fileio'
		 * is the Linux version.
		 *
		 * NOTE: Only for IET
		 */
		if (iscsi_implementation == 1 && 
		    (strcmp(dup_value, "disk") == 0 ||
		     strcmp(dup_value, "tape") == 0))
			strncpy(dup_value, "fileio", 10);

		strncpy(opts->type, dup_value, sizeof (opts->type));
		opts->type [sizeof(opts->type)-1] = '\0';
	}

	if (strcmp(key, "iomode") == 0) {
		/* Make sure it's a valid iomode */
		if (strcmp(dup_value, "wb") != 0 &&
		    strcmp(dup_value, "ro") != 0 &&
		    strcmp(dup_value, "wt") != 0)
			return SA_SYNTAX_ERR;

		if (strcmp(opts->type, "blockio") == 0 &&
		    strcmp(dup_value, "wb") == 0)
			/* Can't do write-back cache with blockio */
			strncpy(dup_value, "wt", 3);

		strncpy(opts->iomode, dup_value, sizeof (opts->iomode));
		opts->iomode [sizeof(opts->iomode)-1] = '\0';
	}

	if (strcmp(key, "lun") == 0) {
		lun = atoi(dup_value);
		if (lun >= 0 && lun <= 16384)
			opts->lun = lun;
		else
			return SA_SYNTAX_ERR;
	}

	if (strcmp(key, "blocksize") == 0) {
		/* Make sure it's a valid blocksize */
		if (strcmp(dup_value, "512")  != 0 &&
		    strcmp(dup_value, "1024") != 0 &&
		    strcmp(dup_value, "2048") != 0 &&
		    strcmp(dup_value, "4096") != 0)
			return SA_SYNTAX_ERR;

		opts->blocksize = atoi(dup_value);
	}

	return SA_OK;
}

/**
 * Takes a string containing share options (e.g. "name=Whatever,lun=3")
 * and converts them to a NULL-terminated array of options.
 */
static int
iscsi_get_shareopts(sa_share_impl_t impl_share, const char *shareopts,
		    iscsi_shareopts_t **opts)
{
	char iqn[255];
	int rc;
	iscsi_shareopts_t *new_opts;
	uint64_t blocksize;
	zfs_handle_t *zhp;

	assert(opts != NULL);
	*opts = NULL;

	new_opts = (iscsi_shareopts_t *) calloc(sizeof (iscsi_shareopts_t), 1);
	if (new_opts == NULL)
		return SA_NO_MEMORY;

	/* Set defaults */
	if (impl_share && impl_share->dataset) {
		if (iscsi_generate_target(impl_share->dataset, iqn,
					  sizeof (iqn)) < 0)
			return SA_SYSTEM_ERR;

		strncpy(new_opts->name, iqn, strlen(iqn));
		new_opts->name [strlen(iqn)+1] = '\0';
	} else
		new_opts->name[0] = '\0';

	if (impl_share && impl_share->handle && impl_share->handle->zfs_libhandle) {
		/* Get the volume blocksize */
		zhp = zfs_open(impl_share->handle->zfs_libhandle,
			       impl_share->dataset,
			       ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME);

		if (zhp == NULL)
			return SA_SYSTEM_ERR;

		blocksize = zfs_prop_get_int(zhp, ZFS_PROP_VOLBLOCKSIZE);

		zfs_close(zhp);

		if (blocksize == 512 || blocksize == 1024 ||
		    blocksize == 2048 || blocksize == 4096)
			new_opts->blocksize = blocksize;
		else
			new_opts->blocksize = 4096;
	} else
		new_opts->blocksize = 4096;

	strncpy(new_opts->iomode, "wt", 3);
	strncpy(new_opts->type, "blockio", 10);
	new_opts->lun = 0;
	*opts = new_opts;

	rc = foreach_shareopt(shareopts, iscsi_get_shareopts_cb, *opts);
	if (rc != SA_OK) {
		free(*opts);
		*opts = NULL;
	}

	return rc;
}

static int
iscsi_enable_share_one_iet(sa_share_impl_t impl_share, int tid)
{
	char *argv[10], params_name[255], params[255], tid_s[11];
	char *shareopts;
	iscsi_shareopts_t *opts;
	int rc;

	opts = (iscsi_shareopts_t *) malloc(sizeof (iscsi_shareopts_t));
	if (opts == NULL)
		return SA_NO_MEMORY;

	/* Get any share options */
	shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;
	rc = iscsi_get_shareopts(impl_share, shareopts, &opts);
	if (rc < 0) {
		free(opts);
		return SA_SYSTEM_ERR;
	}

#ifdef DEBUG
	fprintf(stderr, "iscsi_enable_share_one: name=%s, tid=%d, sharepath=%s, "
		"iomode=%s, type=%s, lun=%d, blocksize=%d\n",
		opts->name, tid, impl_share->sharepath, opts->iomode,
		opts->type, opts->lun, opts->blocksize);
#endif

	/*
	 * ietadm --op new --tid $next --params Name=$iqn
	 * ietadm --op new --tid $next --lun=0 --params \
	 *   Path=/dev/zvol/$sharepath,Type=<fileio|blockio|nullio>
	 */

	/* ====== */
	/* PART 1 - do the (inital) share. No path etc... */
	snprintf(params_name, sizeof (params_name), "Name=%s", opts->name);

	/* int: between -2,147,483,648 and 2,147,483,647 => 10 chars + NUL */
	snprintf(tid_s, sizeof(tid_s), "%d", tid);

	argv[0] = IETM_CMD_PATH;
	argv[1] = (char*)"--op";
	argv[2] = (char*)"new";
	argv[3] = (char*)"--tid";
	argv[4] = tid_s;
	argv[5] = (char*)"--params";
	argv[6] = params_name;
	argv[7] = NULL;

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc < 0) {
		free(opts);
		return SA_SYSTEM_ERR;
	}

	/* ====== */
	/* PART 2 - Set share path and lun. */
	snprintf(params, sizeof (params),
		 "Path=%s,Type=%s,iomode=%s,BlockSize=%d",
		 impl_share->sharepath, opts->type, opts->iomode,
		 opts->blocksize);

	argv[5] = (char*)"--lun";
	snprintf(argv[6], sizeof(argv[6]), "%d", opts->lun);
	argv[7] = (char*)"--params";
	argv[8] = params;
	argv[9] = NULL;

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc < 0) {
		free(opts);
		return SA_SYSTEM_ERR;
	}

	/* ====== */
	/* PART 3 - Run local update script. */
	if (access(EXTRA_SHARE_SCRIPT, X_OK) == 0) {
		argv[0] = (char*)EXTRA_SHARE_SCRIPT;
		argv[1] = tid_s;
		argv[2] = NULL;

		rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
		if (rc < 0) {
			free(opts);
			return SA_SYSTEM_ERR;
		}
	}

	free(opts);
	return SA_OK;
}

/* NOTE: TID is not use with SCST - it's autogenerated at create time. */
static int
iscsi_enable_share_one_scst(sa_share_impl_t impl_share, int tid)
{
	char *argv[3], *shareopts, *device, buffer[255], path[PATH_MAX];
	iscsi_shareopts_t *opts;
	int rc;

#ifdef DEBUG
	fprintf(stderr, "iscsi_enable_share_one: tid=%d, sharepath=%s\n",
		tid, impl_share->sharepath);
#endif

	opts = (iscsi_shareopts_t *) malloc(sizeof (iscsi_shareopts_t));
	if (opts == NULL)
		return SA_NO_MEMORY;

	/* Get any share options */
	shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;
	rc = iscsi_get_shareopts(impl_share, shareopts, &opts);
	if (rc < 0) {
		free(opts);
		return SA_SYSTEM_ERR;
	}

	/* Generate a scst device name from the dataset name */
	iscsi_generate_device_name(impl_share->dataset, &device);

#ifdef DEBUG
	fprintf(stderr, "iscsi_enable_share_one: name=%s, iomode=%s, type=%s, lun=%d, blocksize=%d\n",
		opts->name, opts->iomode, opts->type, opts->lun, opts->blocksize);
#endif

	/* ====== */
	/* PART 1 - Add target */
	// echo "add_target $name" > $SYSFS/targets/iscsi/mgmt
	strcpy(path, "targets/iscsi/mgmt");
	sprintf(buffer, "add_target %s", opts->name);
	iscsi_write_sysfs_value(path, buffer);

	/* ====== */
	/* PART 2 - Add device */
	// echo "add_device $dev filename=/dev/zvol/$vol; blocksize=512" > $SYSFS/handlers/vdisk_blockio/mgmt
	sprintf(path, "handlers/vdisk_%s/mgmt", opts->type);
	sprintf(buffer, "add_device %s filename=%s; blocksize=%d",
		device, impl_share->sharepath, opts->blocksize);
	iscsi_write_sysfs_value(path, buffer);

	/* ====== */
	/* PART 3 - Add lun */
	// echo "add $dev 0" > $SYSFS/targets/iscsi/$name/luns/mgmt
	sprintf(path, "targets/iscsi/%s/luns/mgmt", opts->name);
	sprintf(buffer, "add %s %d", device, opts->lun);
	iscsi_write_sysfs_value(path, buffer);

	/* ====== */
	/* PART 4 - Enable target */
	// echo 1 > $SYSFS/targets/iscsi/$name/enabled
	sprintf(path, "targets/iscsi/%s/enabled", opts->name);
	strcpy(buffer, "1");
	iscsi_write_sysfs_value(path, buffer);

	/* ====== */
	/* PART 5 - Run local update script. */
	if (access(EXTRA_SHARE_SCRIPT, X_OK) == 0) {
		argv[0] = (char*)EXTRA_SHARE_SCRIPT;
		argv[1] = opts->name;
		argv[2] = NULL;

		rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
		if (rc < 0) {
			free(opts);
			return SA_SYSTEM_ERR;
		}
	}

	free(opts);

	return SA_OK;
}

/* WRAPPER: Depending on iSCSI implementation, call the relevant function */
static int
iscsi_enable_share_one(sa_share_impl_t impl_share, int tid)
{
	int rc;

	if (iscsi_implementation == 1)
		rc = iscsi_enable_share_one_iet(impl_share, tid);
	else if (iscsi_implementation == 2)
		rc = iscsi_enable_share_one_scst(impl_share, tid);

	return rc;
}

static int
iscsi_enable_share(sa_share_impl_t impl_share)
{
	char *shareopts;
	int tid = 0;

	if (!iscsi_available())
		return SA_SYSTEM_ERR;

	shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;
	if (shareopts == NULL) /* on/off */
		return SA_SYSTEM_ERR;

	if (strcmp(shareopts, "off") == 0)
		return SA_OK;

	/* Retreive the list of (possible) active shares */
	iscsi_retrieve_targets();

	/* Go through list of targets, get next avail TID. */
	while (iscsi_targets != NULL) {
		tid = iscsi_targets->tid;

		if (iscsi_targets->session && iscsi_targets->session->state)
			return SA_OK;

		iscsi_targets = iscsi_targets->next;
	}
	tid++; /* Next TID is/should be availible */

	/* Magic: Enable (i.e., 'create new') share */
	return iscsi_enable_share_one(impl_share, tid);
}

static int
iscsi_disable_share_one_iet(int tid)
{
	char *argv[6];
	char tid_s[11];
	int rc;

	/* int: between -2,147,483,648 and 2,147,483,647 => 10 chars + NUL */
	snprintf(tid_s, sizeof (tid_s), "%d", tid);

	argv[0] = IETM_CMD_PATH;
	argv[1] = (char*)"--op";
	argv[2] = (char*)"delete";
	argv[3] = (char*)"--tid";
	argv[4] = tid_s;
	argv[5] = NULL;

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc < 0)
		return SA_SYSTEM_ERR;
	else
		return SA_OK;
}

static int
iscsi_disable_share_one_scst(int tid)
{
	char path[PATH_MAX], buffer[255];

	/* Retreive the list of (possible) active shares */
	iscsi_retrieve_targets();

	while (iscsi_targets != NULL) {
		if (iscsi_targets->tid == tid) {
#ifdef DEBUG
			fprintf(stderr, "iscsi_disable_share_one_scst: target=%s, tid=%d, path=%s, device=%s\n",
				iscsi_targets->name, iscsi_targets->tid, iscsi_targets->path, iscsi_targets->iotype);
#endif

			break;
		}

		iscsi_targets = iscsi_targets->next;
	}

	/* ====== */
	/* PART 1 - Disable target */
	// echo 0 > $SYSFS/targets/iscsi/$name/enabled
	sprintf(path, "targets/iscsi/%s/enabled", iscsi_targets->name);
	strcpy(buffer, "0");
	iscsi_write_sysfs_value(path, buffer);

	/* ====== */
	/* PART 2 - Delete device */
        // dev=`/bin/ls -l $SYSFS/targets/iscsi/$name/luns/0/device | sed 's@.*/@@'`
        // echo "del_device $dev" > $SYSFS/handlers/vdisk_blockio/mgmt
	sprintf(path, "handlers/vdisk_%s/mgmt", iscsi_targets->iotype);
	sprintf(buffer, "del_device %s", iscsi_targets->device);
	iscsi_write_sysfs_value(path, buffer);

	/* ====== */
	/* PART 3 - Delete target */
        // echo "del_target $name" > $SYSFS/targets/iscsi/mgmt
	strcpy(path, "targets/iscsi/mgmt");
	sprintf(buffer, "del_target %s", iscsi_targets->name);
	iscsi_write_sysfs_value(path, buffer);

	return SA_OK;
}

/* WRAPPER: Depending on iSCSI implementation, call the relevant function */
static int
iscsi_disable_share_one(int tid)
{
	int rc = SA_OK;

	if (iscsi_implementation == 1)
		rc = iscsi_disable_share_one_iet(tid);
	else if (iscsi_implementation == 2)
		rc = iscsi_disable_share_one_scst(tid);

	return rc;
}

static int
iscsi_disable_share(sa_share_impl_t impl_share)
{
	if (!iscsi_available()) {
		/*
		 * The share can't possibly be active, so nothing
		 * needs to be done to disable it.
		 */
		return SA_OK;
	}

	/* Retreive the list of (possible) active shares */
	iscsi_retrieve_targets();
	while (iscsi_targets != NULL) {
		if (strcmp(impl_share->sharepath, iscsi_targets->path) == 0) {
#ifdef DEBUG
			fprintf(stderr, "iscsi_disable_share: target=%s, tid=%d, path=%s\n",
				iscsi_targets->name, iscsi_targets->tid, iscsi_targets->path);
#endif

			if (iscsi_targets->session && iscsi_targets->session->state) {
				/**
				 * XXX: This will wail twice because sa_disable_share is called
				 *      twice - once with correct protocol (iscsi) and once with
				 *      protocol=NULL
				 */
				fprintf(stderr, "Can't disable share - already active with shares\n");
				return SA_OK;
			}

			return iscsi_disable_share_one(iscsi_targets->tid);
		}

		iscsi_targets = iscsi_targets->next;
	}

	return SA_OK;
}

int
iscsi_disable_share_all(void)
{
	int rc = 0;

	/* Retreive the list of (possible) active shares */
	iscsi_retrieve_targets();

	while (iscsi_targets != NULL) {
#ifdef DEBUG
		fprintf(stderr, "iscsi_disable_share_all: target=%s, tid=%d, path=%s\n",
			iscsi_targets->name, iscsi_targets->tid, iscsi_targets->path);
#endif
		rc += iscsi_disable_share_one(iscsi_targets->tid);

		iscsi_targets = iscsi_targets->next;
	}

	return rc;
}

static boolean_t
iscsi_is_share_active(sa_share_impl_t impl_share)
{
	if (!iscsi_available())
		return B_FALSE;

	/* Retreive the list of (possible) active shares */
	iscsi_retrieve_targets();

	while (iscsi_targets != NULL) {
#ifdef DEBUG
		fprintf(stderr, "iscsi_is_share_active: %s ?? %s\n",
			iscsi_targets->path, impl_share->sharepath);
#endif

		if (strcmp(iscsi_targets->path, impl_share->sharepath) == 0)
			return B_TRUE;

		iscsi_targets = iscsi_targets->next;
	}

	return B_FALSE;
}

static int
iscsi_validate_shareopts(const char *shareopts)
{
	iscsi_shareopts_t *opts;
	int rc = SA_OK;

	rc = iscsi_get_shareopts(NULL, shareopts, &opts);

	free(opts);
	return rc;
}

static int
iscsi_update_shareopts(sa_share_impl_t impl_share, const char *resource,
		       const char *shareopts)
{
	char *shareopts_dup, *old_shareopts, iqn[255];;
	boolean_t needs_reshare = B_FALSE, have_active_sessions = B_FALSE;
	
	if(impl_share->dataset == NULL)
		return B_FALSE;

	/* Does this target have active sessions? */
	iscsi_retrieve_targets();

	while (iscsi_targets != NULL) {
		if ((strcmp(impl_share->sharepath, iscsi_targets->path) == 0) &&
		    iscsi_targets->session && iscsi_targets->session->state) {
			have_active_sessions = B_TRUE;
			break;
		}

		iscsi_targets = iscsi_targets->next;
	}

	FSINFO(impl_share, iscsi_fstype)->active =
		iscsi_is_share_active(impl_share);

	old_shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;

	if (strcmp(shareopts, "on") == 0) {
		/* Force a IQN value. This so that the iqn doesn't change
		 * 'next month' (when it's regenerated again) .
		 * NOTE: Does not change shareiscsi option, only sharetab!
		 */
		if (iscsi_generate_target(impl_share->dataset, iqn, sizeof (iqn)) == 0)
			snprintf(shareopts, strlen(iqn)+6, "name=%s", iqn);
	}

#ifdef DEBUG
	fprintf(stderr, "iscsi_update_shareopts: share=%s;%s,"
		" active=%d, have_active_sessions=%d, new_shareopts=%s, old_shareopts=%s\n",
		impl_share->dataset, impl_share->sharepath,
		FSINFO(impl_share, iscsi_fstype)->active, have_active_sessions,
		shareopts,
		FSINFO(impl_share, iscsi_fstype)->shareopts ?
		FSINFO(impl_share, iscsi_fstype)->shareopts : "null");
#endif

	/* RESHARE if:
	 *  is active
	 *  have old shareopts
	 *  old shareopts != shareopts
	 *  no active sessions
	 */
	if (FSINFO(impl_share, iscsi_fstype)->active && old_shareopts != NULL &&
	    strcmp(old_shareopts, shareopts) != 0 && !have_active_sessions) {
		needs_reshare = B_TRUE;
		iscsi_disable_share(impl_share);
	}

	shareopts_dup = strdup(shareopts);

	if (shareopts_dup == NULL)
		return SA_NO_MEMORY;

	if (old_shareopts != NULL)
		free(old_shareopts);

	FSINFO(impl_share, iscsi_fstype)->shareopts = shareopts_dup;

	if (needs_reshare)
		iscsi_enable_share(impl_share);

	return SA_OK;
}

static void
iscsi_clear_shareopts(sa_share_impl_t impl_share)
{
	free(FSINFO(impl_share, iscsi_fstype)->shareopts);
	FSINFO(impl_share, iscsi_fstype)->shareopts = NULL;
}

static const sa_share_ops_t iscsi_shareops = {
	.enable_share = iscsi_enable_share,
	.disable_share = iscsi_disable_share,

	.validate_shareopts = iscsi_validate_shareopts,
	.update_shareopts = iscsi_update_shareopts,
	.clear_shareopts = iscsi_clear_shareopts,
};

/*
 * Provides a convenient wrapper for determing iscsi availability
 */
static boolean_t
iscsi_available(void)
{
	DIR *sysfs_scst;

	iscsi_implementation = -1;

	/* First check if this is IET */
	if (access(PROC_IET_VOLUME, F_OK) == 0) {
		if (access(IETM_CMD_PATH, X_OK) == 0) {
			iscsi_implementation = 1;

			return B_TRUE;
		}
	} else {
		/* Then check if it's SCST */
		sysfs_scst = opendir(SYSFS_SCST);
		if (sysfs_scst != NULL) {
			iscsi_implementation = 2;
			closedir(sysfs_scst);

			return B_TRUE;
		}
	}

	return B_FALSE;
}

void
libshare_iscsi_init(void)
{
	iscsi_fstype = register_fstype("iscsi", &iscsi_shareops);
}
