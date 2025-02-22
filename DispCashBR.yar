rule DispCashBR_ATM_Rules
{
	meta:
		author = "IT7D3"
		disclaimer = "May detect false-positives"
		description = "Detects DispCashBR ATM malware"

	strings:
		$DispCash_1 = "MSXFS.dll" nocase
		$DispCash_2 = "COMANDO EXECUTADO COM SUCESSO" nocase
		$DispCash_3 = "WFSStartUp" nocase
		$DispCash_4 = "WFSCreateAppHandle" nocase
		$DispCash_5 = "WFSExecute" nocase
		$DispCash_6 = "WFSGetInfo" nocase

	condition:
		4 of ($DispCash_*)
}
