rule Alice_ATM_Rules
{
	meta:
		author = "IT7D3"
		disclaimer = "May detect false-positives"
		description = "Detects Alice ATM malware"

	strings:
		//These 3 detect both Alice2014-* and Alice2020
		$Alice_1 = "msxfs.dll" nocase
		$Alice_2 = "WFSExecute" nocase
		$Alice_3 = "Project Alice" ascii nocase //Alice2014-1 doesn't have this string

		//These 3 detect Alice-2018-*
		$Alice2018_1 = "bknaotkp" nocase
		$Alice2018_2 = "gpfudcjl" nocase
		$Alice2018_3 = ".taggant" nocase

	condition:
		(2 of ($Alice_*)) or (2 of ($Alice2018_*) and filesize > 2000000)
}
