rule FiXS_ATM_Rules
{
	meta:
		author = "IT7D3"
		disclaimer = "May detect false-positives"
		description = "Detects FiXS ATM malware"

	strings:
		$FiXS_1 = "MSXFS.dll" nocase
		$FiXS_2 = "SOFTWARE\\XFS\\PHYSICAL_SERVICES" nocase
		$FiXS_3 = "JanFebMarAprMayJunJulAugSepOctNovDec" nocase
		$FiXS_4 = "SunMonTueWedThuFriSat" nocase
		$FiXS_5 = "WFSExecute" nocase
		$FiXS_6 = "WFSGetInfo" nocase

	condition:
		all of them
}
