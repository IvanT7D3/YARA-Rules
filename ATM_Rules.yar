//Detects the following ATM malware families: Alice, DispCashBR, FiXS, and GreenDispenser

import "pe"

rule Alice
{
	meta:
		author = "IT7D3"
		description = "Detects Alice ATM malware (versions from 2014, 2018 and 2020)"
		disclaimer = "May produce false positives"

	strings:
		$str_project_alice = "Project Alice" ascii wide nocase

		$ui_pin_prompt = "Input PIN-code for access" ascii wide nocase
		$ui_operator_panel = "Operator panel" ascii wide nocase
		$ui_dispense_panel = "Dispense panel" ascii wide nocase
		$ui_cassette_id = "Input cassette ID here" ascii wide nocase
		$ui_dispense_error = "Error %d ocurred" ascii wide nocase
		$ui_cassette_unavail = "cassette is unavailable" ascii wide nocase
		$ui_pin_limit = "PIN-Code input limit was reached" ascii wide nocase
		$ui_cannot_dispense = "Can't dispense requested amount" ascii wide nocase
		$ui_bills_count = "Bills count" ascii wide nocase

		$packer_bknaotkp = "bknaotkp" ascii wide
		$packer_gpfudcjl = "gpfudcjl" ascii wide
		$packer_taggant = ".taggant" ascii wide

		$xfs_execute = "WFSExecute" ascii wide nocase

	condition:
		uint16(0) == 0x5A4D and
		(
			( $str_project_alice and
				( 1 of ($ui_*) or 2 of ($packer_*) or $xfs_execute
				or pe.imports("msxfs.dll")
				or pe.imphash() == "6a102b98e27ed65313b0d92dd1f6dc2d" //Alice-2014-1
				or pe.imphash() == "9c5c09b67b8a01298ebef0250f9d5e55" //Alice-2014-2
				or pe.imphash() == "43cb8bea4ca8c4f791841893add4e86a" //Alice-2014-3 and Alice-2020
				or pe.imphash() == "baa93d47220682c04d92f7797d9224ce" //Alice-2018-1
				or pe.imphash() == "352a7e164921b1abc2cc504c7f96d80b")) //Alice-2018-2
			or (3 of ($ui_*))
			or $xfs_execute and for any sec in pe.sections : ( sec.name == ".vmp0" )
		)
}

rule DispCashBR
{
	meta:
		author = "IT7D3"
		description = "Detects DispCashBR ATM malware (from 2019 and 2021)"
		disclaimer = "May produce false positives"

	strings:
		$str_comando_sucesso = "COMANDO EXECUTADO COM SUCESSO" ascii wide nocase

		$err_hardware = "WFS_ERR_HARDWARE_ERROR: %d" ascii wide nocase
		$err_internal = "WFS_ERR_INTERNAL_ERROR: %d" ascii wide nocase
		$err_software = "WFS_ERR_SOFTWARE_ERROR: %d" ascii wide nocase
		$err_user = "WFS_ERR_USER_ERROR: %d" ascii wide nocase
		$err_canceled = "WFS_ERR_CANCELED: %d" ascii wide nocase
		$err_connection_lost = "WFS_ERR_CONNECTION_LOST: %d" ascii wide nocase
		$err_dev_not_ready = "WFS_ERR_DEV_NOT_READY: %d" ascii wide nocase
		$err_timeout = "WFS_ERR_TIMEOUT: %d" ascii wide nocase
		$err_locked = "WFS_ERR_LOCKED: %d" ascii wide nocase
		$err_invalid_hservice = "[ WFS_ERR_INVALID_HSERVICE: %d ]" ascii wide nocase
		$err_unsupp_command = "WFS_ERR_UNSUPP_COMMAND: %d" ascii wide nocase

		$toolchain_libgcj = "libgcj-16.dll" ascii wide nocase
		$toolchain_report_error = "___report_error" ascii wide nocase

	condition:
		uint16(0) == 0x5A4D and
		(
			($str_comando_sucesso and (2 of ($err_*) or all of ($toolchain_*)))
			or (6 of ($err_*) and $toolchain_libgcj)
			or pe.imphash() == "69a2b15aad3ceb1bc770eec1dc7f1bc1" //DispCashBR-2019-1
			or pe.imphash() == "5d73b1e673b0c8b899b5f2db7b59b63b" //Shared between DispCashBR-2019-2 and DispCashBR-2021
		)
}

rule FiXS
{
	meta:
		author = "IT7D3"
		description = "Detects FiXS ATM malware (2023 versions)"
		disclaimer = "May produce false positives"

	strings:
		$xfs_registry_path = "SOFTWARE\\XFS\\PHYSICAL_SERVICES" ascii wide nocase
		$xfs_execute = "WFSExecute" ascii wide nocase

		$fixs_self_filename = "fixs.exe" ascii wide nocase
		$fixs_cassette_data1 = "Data1 $:" ascii wide
		$fixs_cassette_data6 = "Data6 :" ascii wide
		$fixs_apanas = "Dziadulja Apanas" ascii wide nocase

	condition:
		uint16(0) == 0x5A4D and
		(
			($xfs_registry_path and $xfs_execute and ($fixs_self_filename or 1 of ($fixs_cassette_*) or $fixs_apanas))

			or ($fixs_self_filename and 1 of ($fixs_cassette_*) and pe.imports("kernel32.dll", "WinExec"))
			or pe.imphash() == "9f4693fc0c511135129493f2161d1e86" //FiXS-2023-1
			or pe.imphash() == "d04b0fdb07c8e309824807d361cf5f76" //FiXS-2023-2
		)
}

rule GreenDispenser
{
	meta:
		author = "IT7D3"
		description = "Detects GreenDispenser ATM malware (2015 versions)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/Meet-GreenDispenser"
		disclaimer = "May produce false positives"

	strings:
		$str_bills_left = "Bills left:" ascii wide nocase
		$xfs_err_op_in_progress = "WFS_ERR_OP_IN_PROGRESS" ascii wide nocase

		$gd_dispenser_progname = "dispenserprogm" ascii wide nocase
		$gd_del_exe = "del.exe" ascii wide nocase
		$gd_operator_menu = "Press 1 to dispense money" ascii wide nocase

		$selfwipe_clean_freespace = "Cleaning free space to securely delete" ascii wide nocase
		$selfwipe_cmd_exec = "cmd.exe /C" ascii wide nocase
		$selfwipe_clean_mft = "Cleaning MFT" ascii wide nocase

	condition:
		uint16(0) == 0x5A4D and
		(
			($str_bills_left and $xfs_err_op_in_progress and (1 of ($gd_*) or 1 of ($selfwipe_*)))
			or (2 of ($gd_*) and 1 of ($selfwipe_*))
			or pe.imphash() == "a3e973ceb1a88c866c38a13b6e0bdc9d" //All GreenDispenser-2015
		)
}
