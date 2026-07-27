package main

// itoa is a tiny allocation-light int->string helper used by the mount's unit tests. (The former
// recentWrites tests here were removed with the mount-local self-write tracker, which now lives in
// the clientcore Volume; itoa is kept because other tests in this package still use it.)
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
