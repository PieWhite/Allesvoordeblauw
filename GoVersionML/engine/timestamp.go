// timestamp.go provides high-performance UTC timestamp conversion utilities
// used by the aggregator and window manager to avoid the overhead of
// time.Parse for known timestamp formats.
package engine

var monthDays = [12]int64{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}

func fastUnixTime(year, month, day, hour, minute, second int) int64 {
	y := int64(year)
	m := int64(month)
	d := int64(day)

	prevYear := y - 1
	leapDays := prevYear/4 - prevYear/100 + prevYear/400 - 477

	days := (y-1970)*365 + leapDays

	days += monthDays[m-1]

	if m > 2 && ((year%4 == 0 && year%100 != 0) || (year%400 == 0)) {
		days++
	}

	days += d - 1

	return days*86400 + int64(hour)*3600 + int64(minute)*60 + int64(second)
}

func sniffTimestamp(first string) int64 {
	if len(first) >= 23 && first[4] == '-' && first[10] == 'T' {
		year := int(first[0]-'0')*1000 + int(first[1]-'0')*100 + int(first[2]-'0')*10 + int(first[3]-'0')
		month := int(first[5]-'0')*10 + int(first[6]-'0')
		day := int(first[8]-'0')*10 + int(first[9]-'0')
		hour := int(first[11]-'0')*10 + int(first[12]-'0')
		minute := int(first[14]-'0')*10 + int(first[15]-'0')
		second := int(first[17]-'0')*10 + int(first[18]-'0')

		sec := fastUnixTime(year, month, day, hour, minute, second)
		return (sec / 300) * 300
	}

	if len(first) >= 19 && first[4] == '-' && first[10] == ' ' {
		year := int(first[0]-'0')*1000 + int(first[1]-'0')*100 + int(first[2]-'0')*10 + int(first[3]-'0')
		month := int(first[5]-'0')*10 + int(first[6]-'0')
		day := int(first[8]-'0')*10 + int(first[9]-'0')
		hour := int(first[11]-'0')*10 + int(first[12]-'0')
		minute := int(first[14]-'0')*10 + int(first[15]-'0')
		second := int(first[17]-'0')*10 + int(first[18]-'0')

		sec := fastUnixTime(year, month, day, hour, minute, second)
		return (sec / 300) * 300
	}
	return 0
}
