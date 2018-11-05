#
# Copyright (C) 2010 OpenWrt.org
#

. /lib/platform.sh

BOOT_NAME=u-boot
if [ -z "$(cat /proc/mtd | grep -w firmware_backup)" ]; then
PART_NAME=firmware
else
PART_NAME=firmware_backup
fi
RAMFS_COPY_DATA=/lib/platform.sh

platform_leds_blink() {
	. /lib/functions/leds.sh

	led_count=$(ls -al /sys/class/leds/ | grep "^l" | wc -l)
	led_delay_on=500
	let timer_count=led_count*1000
	let timer_count=timer_count-led_delay_on

	ls_file=$(ls /sys/class/leds)
	for filename in $ls_file
	do
		led_timer $filename $led_delay_on $timer_count
		sleep 1
	done
}

platform_check_image() {
	return 0
}

okos_get_magic_word() {
    (dd if=$1 bs=$((0x00140000)) count=1 skip=1 | hexdump -v -n 2 -e '1/1 "%02x"') 2>/dev/null
}

platform_mtk_check_image() {
	local board=$(mtk_board_name)
	local board_flash=$(mtk_board_flash)
    # OK_PATCH
    local magic="$(get_magic_word "$1")"
    local okos_magic="$(okos_get_magic_word "$1")"

	[ "$#" -gt 1 ] && return 1

    [ "$magic" = "2705" -a "$okos_magic" != "2705" ] && {
        export "OKOS_UPGRADE=1"
        return 1
    }

	case "$board_flash" in
	"nand")
		img_chk -b "$board" -o 0x80000 -f "$1" -m >>$UPGRADE_LOG_FILE 2>&1
		;;
	*)
		img_chk -b "$board" -o 0x30000 -f "$1" >>$UPGRADE_LOG_FILE 2>&1
		;;
	esac

	return "$?"
}

platform_mtk_upgrade() {
	sync
	sync

	umount_storage
	platform_leds_blink
	upgrade_log "memory"
	upgrade_log "mount"
	ps >>$UPGRADE_LOG_FILE
	upgrade_log_end

	if [ "$UPGRADE_BOOT" -eq 1 ]; then
		img_bootloader_ver="$(mtkmips_get_img_ver "$1")"
		bootloader_ver="$(mtkmips_get_bootloader_ver "$1")"

		if [[ "$img_bootloader_ver" -gt "$bootloader_ver" ]]; then
			upgrade_log "upgrade uboot"
			get_image "$1" | dd bs=2k count=96 conv=sync 2>/dev/null | mtd write - "${BOOT_NAME:-image}" >>$UPGRADE_LOG_FILE 2>&1
			upgrade_log_end
		fi

		if [ "$SAVE_CONFIG" -eq 1 ]; then
			get_image "$1" | dd bs=2k skip=160 conv=sync 2>/dev/null | mtd $MTD_CONFIG_ARGS -j "$CONF_TAR" write - "${PART_NAME:-image}" >>$UPGRADE_LOG_FILE 2>&1
		else
			get_image "$1" | dd bs=2k skip=160 conv=sync 2>/dev/null | mtd write - "${PART_NAME:-image}" >>$UPGRADE_LOG_FILE 2>&1
		fi
	else
		default_do_upgrade "$ARGV"
	fi

	ret=$?

	if [ "$ret" -eq 0 ]; then
		upgrade_log "mtd ok"
	else
		upgrade_log "mtd failed with $ret"
	fi
	upgrade_log_end
}

platform_mtk_okos_nand_upgrade() {
	sync
	sync

	umount_storage
	platform_leds_blink
	upgrade_log "memory"
	upgrade_log "mount"
	ps >>$UPGRADE_LOG_FILE
	upgrade_log_end
    PART_NAME=firmware

	get_image "$1" | mtd write - "${PART_NAME:-image}" >>$UPGRADE_LOG_FILE 2>&1

	ret=$?

	if [ "$ret" -eq 0 ]; then
		upgrade_log "mtd ok"
	else
		upgrade_log "mtd failed with $ret"
	fi
	upgrade_log_end
}

platform_mtk_nand_upgrade() {
	sync
	sync

	umount_storage
	platform_leds_blink
	upgrade_log "memory"
	upgrade_log "mount"
	ps >>$UPGRADE_LOG_FILE
	upgrade_log_end

	if [ "$UPGRADE_BOOT" -eq 1 ]; then
		img_bootloader_ver="$(mtkmips_get_img_ver_nand "$1")"
		bootloader_ver="$(mtkmips_get_bootloader_ver "$1")"

		if [[ "$img_bootloader_ver" -gt "$bootloader_ver" ]]; then
			upgrade_log "upgrade uboot"
			get_image "$1" | dd bs=2k count=128 conv=sync 2>/dev/null | mtd write - "${BOOT_NAME:-image}" >>$UPGRADE_LOG_FILE 2>&1
			upgrade_log_end
		fi

		# squashfs + ubifs, skip 1280K
		get_image "$1" | dd bs=2k skip=640 conv=sync 2>/dev/null | mtd write - "${PART_NAME:-image}" >>$UPGRADE_LOG_FILE 2>&1
	else
		get_image "$1" | mtd write - "${PART_NAME:-image}" >>$UPGRADE_LOG_FILE 2>&1
	fi

	ret=$?

	if [ "$ret" -eq 0 ]; then
		upgrade_log "mtd ok"
	else
		upgrade_log "mtd failed with $ret"
	fi
	upgrade_log_end
}

platform_mtk_copy_config() {
	local board_flash=$(mtk_board_flash)

	case "$board_flash" in
	"nand")
		upgrade_log "Save config"
		rm -rf $1/*
		cp -af "$CONF_TAR" $1/
		sync
		;;
	esac
}

platform_mtk_remove_config() {
	local board_flash=$(mtk_board_flash)

	case "$board_flash" in
	"nand")
		upgrade_log "Drop config"
		rm -rf $1/*
		;;
	esac
}

platform_do_upgrade() {
	local board_flash=$(mtk_board_flash)

	case "$board" in
	"nand")
		platform_mtk_nand_upgrade "$ARGV"
		;;
	*)
		platform_mtk_upgrade "$ARGV"
		;;
	esac
}

platform_firmware_okos_upgrade() {
	. /lib/functions.sh

	fm=$(find_mtd_index "firmware")
	if [ -n "$fm" ]; then
		local board_flash=$(mtk_board_flash)

		case "$board_flash" in
		"nand")
			upgrade_log "start okos($board_flash)"
			platform_mtk_okos_nand_upgrade "$ARGV"
			if [ "$SAVE_CONFIG" -eq 1 ] && type 'platform_mtk_copy_config' >/dev/null 2>/dev/null; then
				platform_mtk_copy_config /overlay
			fi

			if [ "$SAVE_CONFIG" -eq 0 ] && type 'platform_mtk_remove_config' >/dev/null 2>/dev/null; then
				platform_mtk_remove_config /overlay
			fi
			;;
		*)
			upgrade_log "start okos($board_flash)"
			platform_mtk_upgrade "$ARGV"
			;;
		esac

		sync
		reboot -f
		sleep 1
		force_reboot
		exit 1
	fi
}

platform_firmware_backup_upgrade() {
	. /lib/functions.sh

	fbackup=$(find_mtd_index "firmware_backup")
	if [ -n "$fbackup" ]; then
		local board_flash=$(mtk_board_flash)

		case "$board_flash" in
		"nand")
			upgrade_log "start backup($board_flash)"
			platform_mtk_nand_upgrade "$ARGV"
			if [ "$SAVE_CONFIG" -eq 1 ] && type 'platform_mtk_copy_config' >/dev/null 2>/dev/null; then
				platform_mtk_copy_config /overlay
			fi

			if [ "$SAVE_CONFIG" -eq 0 ] && type 'platform_mtk_remove_config' >/dev/null 2>/dev/null; then
				platform_mtk_remove_config /overlay
			fi
			;;
		*)
			upgrade_log "start backup($board_flash)"
			platform_mtk_upgrade "$ARGV"
			;;
		esac

		sync
		reboot -f
		sleep 1
		force_reboot
		exit 1
	fi
}

disable_watchdog() {
	killall watchdog
	( ps | grep -v 'grep' | grep '/dev/watchdog' ) && {
		echo 'Could not disable watchdog'
		return 1
	}
}

append sysupgrade_pre_upgrade disable_watchdog
