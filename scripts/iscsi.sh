#!/bin/bash

SYSFS=/sys/kernel/scst_tgt

BASETANK="share"
DATE=`date "+%Y%m%d"`

TEST_ISCSI=0
TEST_DESTROY=0

if [ -z "$1" ]; then
	echo "Usage: `basename $0` [unpack]<[iscsi][snapshot][all]>"
	exit 1
fi

set_onoff() {
	type="$1"
	dataset="$2"
	toggle="$3"

	current=`zfs get -H $type -o value $dataset`
	if [ "$current" != "$toggle" ]; then
		run "zfs set $type=$toggle $dataset"
	fi
}

check_exists() {
	dataset="$1"

	extra=""
	[ -n "$2" ] && extra="$2"

	zfs get all "$dataset" > /dev/null 2>&1
	if [ $? != 0 ]; then
		run "zfs create $extra $dataset"
	fi
}

check_shares() {
	if [ "$TEST_ISCSI" == "1" ]; then
		if [ -d $SYSFS ]; then
		    find $SYSFS/targets/iscsi/iqn.* 2> /dev/null
		elif [ -f /proc/net/iet/volume ]; then
		    cat /proc/net/iet/volume
		fi
		echo
	fi

	sleep 2
}

test_header() {
	printf "TEST: %s\n" "$*"
	echo "======================================"
}

run() {
	cmd="$*"

	echo "CMD: $cmd"
	$cmd
}

# ---------
# Needs more work...
if echo "$*" | grep -qi "unpack"; then
	[ ! -c /dev/zfs ] && modprobe zfs

	zfs unmount -a
	zfs unshare -a
	run "zfs destroy -r $BASETANK/tests"

	sh /etc/init.d/zfs stop

	if [ -d $SYSFS ]; then
		find $SYSFS/targets/iscsi/iqn.* -maxdepth 0 2> /dev/null | \
		    while read dir; do
			name=`echo "$dir" | sed 's@.*/@@'`

			echo 0 > $SYSFS/targets/iscsi/$name/enabled

			find $dir/luns/? -maxdepth 0 \
			    -type d 2> /dev/null | \
			    while read lun; do
				lun=`echo "$lun" | sed 's@.*/@@'`
				device=`/bin/ls -l  $dir/luns/$lun/device \
				    | sed 's@.*/@@'`
				echo "del_device $device" > $SYSFS/handlers/vdisk_blockio/mgmt
			    done

			echo "del_target $name" > $SYSFS/targets/iscsi/mgmt
		    done
	elif [ -f /proc/net/iet/volume ]; then
		for tid in `grep ^tid /proc/net/iet/volume | sed "s@.*:\([0-9].*\) name.*@\1@"`
		do
			ietadm --op delete --tid $tid
		done
	fi

	set -e
	rmmod `lsmod | grep ^z | grep -v zlib_deflate | sed 's@ .*@@'` spl zlib_deflate

	pushd / > /dev/null 
	[ -f "tmp/zfs.tgz" ] && tar xzf tmp/zfs.tgz && rm tmp/zfs.tgz
	[ -f "tmp/spl.tgz" ] && tar xzf tmp/spl.tgz && rm tmp/spl.tgz
	popd > /dev/null 

	depmod -a

	sh /etc/init.d/zfs start
	set +e
fi

if echo "$*" | egrep -qi "iscsi|snapshot|all"; then
	check_exists $BASETANK/tests
fi

# ---------
if echo "$*" | egrep -qi "iscsi|all"; then
	TEST_ISCSI=1

	for volnr in 1 2 3; do
		check_exists $BASETANK/tests/iscsi$volnr "-V 15G"
	done

	str=
	for volnr in 1 2 3; do
		str="$str $BASETANK/tests/iscsi$volnr"
	done
	run "zfs get shareiscsi $str"
	check_shares

	for volnr in 1 2 3; do
		set_onoff shareiscsi $BASETANK/tests/iscsi$volnr on
	done

	for volnr in 1 2 3; do
		run "zfs share $BASETANK/tests/iscsi$volnr"
		check_shares
	done

	for volnr in 2 1 3; do
		run "zfs unshare $BASETANK/tests/iscsi$volnr"
		check_shares
	done
fi

# ---------
if echo "$*" | egrep -qi "iscsi|all"; then
	test_header "Share + Unshareall"

	run "zfs share -a" ; check_shares
	run "zfs unshare -a" ; check_shares
fi

# ---------
if echo "$*" | grep -qi "snapshot|all"; then
	test_header "Snapshots"

	echo ; echo "-------------------"
	check_exists $BASETANK/tests/destroy
	check_exists $BASETANK/tests/destroy/destroy1
	run "zfs destroy -r $BASETANK/tests/destroy"

	echo ; echo "-------------------"
	check_exists $BASETANK/tests/destroy
	run "zfs snapshot $BASETANK/tests/destroy@$DATE"
	run "zfs destroy -r $BASETANK/tests/destroy"

	echo ; echo "-------------------"
	check_exists $BASETANK/tests/destroy
	run "zfs snapshot $BASETANK/tests/destroy@$DATE"
	run "zfs destroy -r $BASETANK/tests/destroy@$DATE"
	run "zfs destroy -r $BASETANK/tests/destroy"
fi

if echo "$*" | egrep -qi "iscsi|snapshot|all"; then
	test_header "Cleanup (Share + Destroy all)"

	run "zfs share -a"
	check_shares

	run "zfs destroy -r $BASETANK/tests"
	check_shares

	run "zfs list"
fi
