package config

import "time"

// ianaTimezoneAliases maps IANA backward-compatibility links to their primary
// identifiers. Browser/runtime ICU differences can emit either identifier for
// the same zone; canonicalizing here keeps site.timezone stable.
var ianaTimezoneAliases = map[string]string{
	"Africa/Asmera":         "Africa/Asmara",
	"America/Buenos_Aires":  "America/Argentina/Buenos_Aires",
	"America/Coral_Harbour": "America/Atikokan",
	"America/Godthab":       "America/Nuuk",
	"Asia/Calcutta":         "Asia/Kolkata",
	"Asia/Katmandu":         "Asia/Kathmandu",
	"Asia/Macao":            "Asia/Macau",
	"Asia/Rangoon":          "Asia/Yangon",
	"Asia/Saigon":           "Asia/Ho_Chi_Minh",
	"Asia/Thimbu":           "Asia/Thimphu",
	"Asia/Ulan_Bator":       "Asia/Ulaanbaatar",
	"Atlantic/Faeroe":       "Atlantic/Faroe",
	"Europe/Kiev":           "Europe/Kyiv",
	"Europe/Uzhgorod":       "Europe/Kyiv",
	"Europe/Zaporozhye":     "Europe/Kyiv",
	"Pacific/Enderbury":     "Pacific/Kanton",
	"Pacific/Ponape":        "Pacific/Pohnpei",
	"Pacific/Truk":          "Pacific/Chuuk",
}

// canonicalizeIANATimezone substitutes a backward link when the primary
// identifier is available in the current tzdata runtime.
func canonicalizeIANATimezone(tz string) string {
	target, ok := ianaTimezoneAliases[tz]
	if !ok {
		return tz
	}
	if _, err := time.LoadLocation(target); err != nil {
		return tz
	}
	return target
}
