/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 *
 * This is transpiled from C. Replace asap.
 */

package syntax

import (
	"bytes"
	"unsafe"
)

func toByteSlice(a *byte, length int32) []byte {
	header := struct {
		ptr unsafe.Pointer
		len int
		cap int
	}{
		unsafe.Pointer(a),
		int(length),
		int(length),
	}
	return (*(*[]byte)(unsafe.Pointer(&header)))[:]
}

func cStrlen(a *byte) int32 {
	for i := 0; ; i++ {
		if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(a)) + uintptr(i))) == 0 {
			return int32(i)
		}
	}
}

func cMemcmp(src1, src2 unsafe.Pointer, n int32) int32 {
	b1 := toByteSlice((*byte)(src1), n)
	b2 := toByteSlice((*byte)(src2), n)
	return int32(bytes.Compare(b1, b2))
}

func cNotInt32(x int32) int32 {
	if x == 0 {
		return 1
	}

	return 0
}

func cNotUint32(x uint32) uint32 {
	if x == 0 {
		return 1
	}

	return 0
}

func cNotInt8(x int8) int8 {
	if x == 0 {
		return 1
	}

	return 0
}

type highlight int32

const (
	highlightSection      highlight = 0
	highlightField                  = 1
	highlightPrivateKey             = 2
	highlightPublicKey              = 3
	highlightPresharedKey           = 4
	highlightIP                     = 5
	highlightCidr                   = 6
	highlightHost                   = 7
	highlightPort                   = 8
	highlightMTU                    = 9
	highlightKeepalive              = 10
	highlightComment                = 11
	highlightDelimiter              = 12
	highlightTable                  = 13
	highlightFwMark                 = 14
	highlightSaveConfig             = 15
	highlightCmd                    = 16
	highlightError                  = 17
)

type highlightSpan struct {
	t   highlight
	s   uint32
	len uint32
}
type string_span_t struct {
	s   *byte
	len uint32
}

func is_decimal(c byte) int8 {
	return int8(int8(func(val bool) int32 {
		if val {
			return 1
		} else {
			return 0
		}
	}(int32(c) >= int32('0') && int32(c) <= int32('9'))))
}

func is_hexadecimal(c byte) int8 {
	return int8(int8(func(val bool) int32 {
		if val {
			return 1
		} else {
			return 0
		}
	}(int32(int8(is_decimal(c))) != 0 || int32(c)|int32(32) >= int32('a') && int32(c)|int32(32) <= int32('f'))))
}

func is_alphabet(c byte) int8 {
	return int8(int8(func(val bool) int32 {
		if val {
			return 1
		} else {
			return 0
		}
	}(int32(c)|int32(32) >= int32('a') && int32(c)|int32(32) <= int32('z'))))
}

func is_same(s string_span_t, c *byte) int8 {
	var len = uint32(uint32(cStrlen(c)))
	if len != uint32(s.len) {
		return int8(int8(int32(0)))
	}
	return int8(int8(cNotInt32(cMemcmp(unsafe.Pointer(s.s), unsafe.Pointer(c), int32(uint32(uint32(len)))))))
}

func is_caseless_same(s string_span_t, c *byte) int8 {
	var len = uint32(uint32(cStrlen(c)))
	if len != uint32(s.len) {
		return int8(int8(int32(0)))
	}
	{
		var i = uint32(int32(0))
		for ; i < len; i++ {
			var a = *((*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(c)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*c))))
			var b = *((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))
			if uint32(a)-uint32('a') < uint32(int32(26)) {
				a &= byte(byte(int32(95)))
			}
			if uint32(b)-uint32('a') < uint32(int32(26)) {
				b &= byte(byte(int32(95)))
			}
			if int32(a) != int32(b) {
				return int8(int8(int32(0)))
			}
		}
	}
	return int8(int8(int32(1)))
}

func is_valid_key(s string_span_t) int8 {
	if uint32(s.len) != uint32(uint32(int32(44))) || int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(43))*unsafe.Sizeof(*tempVar))
	}()))) != int32('=') {
		return int8(int8(int32(0)))
	}
	{
		var i = uint32(int32(0))
		for ; i < uint32(uint32(int32(42))); i++ {
			if int8(cNotInt8(is_decimal(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))))) != 0 && int8(cNotInt8(is_alphabet(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))))) != 0 && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('/') && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('+') {
				return int8(int8(int32(0)))
			}
		}
	}
	switch int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(42))*unsafe.Sizeof(*tempVar))
	}()))) {
	case 'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '4', '8', '0':
		{
		}
	default:
		{
			return int8(int8(int32(0)))
		}
	}
	return int8(int8(int32(1)))
}

func is_valid_hostname(s string_span_t) int8 {
	var num_digit = uint32(int32(0))
	var num_entity = uint32(s.len)
	if uint32(s.len) > uint32(uint32(int32(63))) || uint32(cNotUint32(uint32(s.len))) != 0 {
		return int8(int8(int32(0)))
	}
	if int32(*s.s) == int32('-') || int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(uint32(s.len)-uint32(uint32(int32(1))))))*unsafe.Sizeof(*tempVar))
	}()))) == int32('-') {
		return int8(int8(int32(0)))
	}
	if int32(*s.s) == int32('.') || int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(uint32(s.len)-uint32(uint32(int32(1))))))*unsafe.Sizeof(*tempVar))
	}()))) == int32('.') {
		return int8(int8(int32(0)))
	}
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if int8(is_decimal(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}())))) != 0 {
				num_digit += 1
				continue
			}
			if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('.') {
				num_entity -= 1
				continue
			}
			if int8(cNotInt8(is_alphabet(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))))) != 0 && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('-') {
				return int8(int8(int32(0)))
			}
			if uint32(i) != 0 && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('.') && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i-uint32(uint32(int32(1))))))*unsafe.Sizeof(*tempVar))
			}()))) == int32('.') {
				return int8(int8(int32(0)))
			}
		}
	}
	return int8(int8(func(val bool) int32 {
		if val {
			return 1
		} else {
			return 0
		}
	}(num_digit != num_entity)))
}

func is_valid_ipv4(s string_span_t) int8 {
	{
		var j uint32
		var i = uint32(int32(0))
		var pos = uint32(int32(0))
		for ; i < uint32(uint32(int32(4))) && pos < uint32(s.len); i++ {
			var val = uint32(int32(0))
			for j = uint32(int32(0)); j < uint32(uint32(int32(3))) && pos+j < uint32(s.len) && int32(int8(is_decimal(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos+j)))*unsafe.Sizeof(*tempVar))
			}()))))) != 0; j++ {
				val = uint32(uint32(uint32(int32(10))*uint32(uint32(val)) + uint32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos+j)))*unsafe.Sizeof(*tempVar))
				}()))) - uint32('0')))
			}
			if j == uint32(uint32(int32(0))) || j > uint32(uint32(int32(1))) && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('0') || val > uint32(uint32(uint32(int32(255)))) {
				return int8(int8(int32(0)))
			}
			if pos+j == uint32(s.len) && i == uint32(uint32(int32(3))) {
				return int8(int8(int32(1)))
			}
			if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos+j)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('.') {
				return int8(int8(int32(0)))
			}
			pos += j + uint32(uint32(int32(1)))
		}
	}
	return int8(int8(int32(0)))
}

func is_valid_ipv6(s string_span_t) int8 {
	var pos = uint32(int32(0))
	var seen_colon = int8(int8(int32(0)))
	if uint32(s.len) < uint32(uint32(int32(2))) {
		return int8(int8(int32(0)))
	}
	if int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos)))*unsafe.Sizeof(*tempVar))
	}()))) == int32(':') && int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(func() uint32 {
			pos += 1
			return pos
		}())))*unsafe.Sizeof(*tempVar))
	}()))) != int32(':') {
		return int8(int8(int32(0)))
	}
	if int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(uint32(s.len)-uint32(uint32(int32(1))))))*unsafe.Sizeof(*tempVar))
	}()))) == int32(':') && int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(uint32(s.len)-uint32(uint32(int32(2))))))*unsafe.Sizeof(*tempVar))
	}()))) != int32(':') {
		return int8(int8(int32(0)))
	}
	{
		var j uint32
		var i = uint32(int32(0))
		for ; pos < uint32(s.len); i++ {
			if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos)))*unsafe.Sizeof(*tempVar))
			}()))) == int32(':') && int8(cNotInt8(seen_colon)) != 0 {
				seen_colon = int8(int8(int32(1)))
				if func() uint32 {
					pos += 1
					return pos
				}() == uint32(s.len) {
					break
				}
				if i == uint32(uint32(int32(7))) {
					return int8(int8(int32(0)))
				}
				continue
			}
			for j = uint32(int32(0)); ; j++ {
				if j < uint32(uint32(int32(4))) && pos+j < uint32(s.len) && int32(int8(is_hexadecimal(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos+j)))*unsafe.Sizeof(*tempVar))
				}()))))) != 0 {
					break
				}
			}
			if j == uint32(uint32(int32(0))) {
				return int8(int8(int32(0)))
			}
			if pos+j == uint32(s.len) && (int32(int8(seen_colon)) != 0 || i == uint32(uint32(int32(7)))) {
				break
			}
			if i == uint32(uint32(int32(7))) {
				return int8(int8(int32(0)))
			}
			if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos+j)))*unsafe.Sizeof(*tempVar))
			}()))) != int32(':') {
				if int32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos+j)))*unsafe.Sizeof(*tempVar))
				}()))) != int32('.') || i < uint32(uint32(int32(6))) && int8(cNotInt8(seen_colon)) != 0 {
					return int8(int8(int32(0)))
				}
				return is_valid_ipv4(string_span_t{(*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(pos)))*unsafe.Sizeof(*tempVar))
				}()), uint32(s.len) - pos})
			}
			pos += j + uint32(uint32(int32(1)))
		}
	}
	return int8(int8(int32(1)))
}

/* Bound this around 32 bits, so that we don't have to write overflow logic. */
func is_valid_uint(s string_span_t, support_hex int8, min uint64, max uint64) int8 {
	var val = uint64(int32(0))
	if uint32(s.len) > uint32(uint32(int32(10))) || uint32(cNotUint32(uint32(s.len))) != 0 {
		return int8(int8(int32(0)))
	}
	if int32(int8(support_hex)) != 0 && uint32(s.len) > uint32(uint32(int32(2))) && int32(*s.s) == int32('0') && int32(*((*byte)(func() unsafe.Pointer {
		tempVar := s.s
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
	}()))) == int32('x') {
		{
			var i = uint32(int32(2))
			for ; i < uint32(s.len); i++ {
				if uint32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}())))-uint32('0') < uint32(int32(10)) {
					val = uint64(uint64(uint32(int32(16))*uint32(uint64(val)) + uint32(int32(*((*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
					}())))-int32('0'))))
				} else if uint32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}())))|uint32(int32(32))-uint32('a') < uint32(int32(6)) {
					val = uint64(uint64(uint32(int32(16))*uint32(uint64(val)) + uint32(int32(*((*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
					}())))|int32(32)) - uint32('a') + uint32(int32(10))))
				} else {
					return int8(int8(int32(0)))
				}
			}
		}
	} else {
		{
			var i = uint32(int32(0))
			for ; i < uint32(s.len); i++ {
				if int8(cNotInt8(is_decimal(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}()))))) != 0 {
					return int8(int8(int32(0)))
				}
				val = uint64(uint64(uint32(int32(10))*uint32(uint64(val)) + uint32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}()))) - uint32('0')))
			}
		}
	}
	return int8(int8(func(val bool) int32 {
		if val {
			return 1
		} else {
			return 0
		}
	}(val <= max && val >= min)))
}

func is_valid_port(s string_span_t) int8 {
	return is_valid_uint(s, int8(int8(int32(0))), uint64(int32(0)), uint64(int32(65535)))
}

func is_valid_mtu(s string_span_t) int8 {
	return is_valid_uint(s, int8(int8(int32(0))), uint64(int32(576)), uint64(int32(65535)))
}

func is_valid_persistentkeepalive(s string_span_t) int8 {
	if int8(is_same(s, &[]byte("off\x00")[0])) != 0 {
		return int8(int8(int32(1)))
	}
	return is_valid_uint(s, int8(int8(int32(0))), uint64(int32(0)), uint64(int32(65535)))
}

func is_valid_fwmark(s string_span_t) int8 {
	if int8(is_same(s, &[]byte("off\x00")[0])) != 0 {
		return int8(int8(int32(1)))
	}
	return is_valid_uint(s, int8(int8(int32(1))), uint64(int32(0)), uint64(4294967295))
}

/* This pretty much invalidates the other checks, but rt_names.c's
 * fread_id_name does no validation aside from this. */
func is_valid_table(s string_span_t) int8 {
	if int8(is_same(s, &[]byte("auto\x00")[0])) != 0 {
		return int8(int8(int32(1)))
	}
	if int8(is_same(s, &[]byte("off\x00")[0])) != 0 {
		return int8(int8(int32(1)))
	}
	if uint32(s.len) < uint32(uint32(int32(512))) {
		return int8(int8(int32(1)))
	}
	return is_valid_uint(s, int8(int8(int32(0))), uint64(int32(0)), uint64(4294967295))
}

func is_valid_saveconfig(s string_span_t) int8 {
	return int8(int8(func(val bool) int32 {
		if val {
			return 1
		} else {
			return 0
		}
	}(int32(int8(is_same(s, &[]byte("true\x00")[0]))) != 0 || int32(int8(is_same(s, &[]byte("false\x00")[0]))) != 0)))
}

/* It's probably not worthwhile to try to validate a bash expression.
 * So instead we just demand non-zero length. */
func is_valid_prepostupdown(s string_span_t) int8 {
	return int8(int8(uint32(uint32(s.len))))
}

func is_valid_scope(s string_span_t) int8 {
	if uint32(s.len) > uint32(uint32(int32(64))) || uint32(cNotUint32(uint32(s.len))) != 0 {
		return int8(int8(int32(0)))
	}
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if int8(cNotInt8(is_alphabet(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))))) != 0 && int8(cNotInt8(is_decimal(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))))) != 0 && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('_') && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('=') && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('+') && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('.') && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) != int32('-') {
				return int8(int8(int32(0)))
			}
		}
	}
	return int8(int8(int32(1)))
}

func is_valid_endpoint(s string_span_t) int8 {
	if uint32(cNotUint32(uint32(s.len))) != 0 {
		return int8(int8(int32(0)))
	}
	if int32(*s.s) == int32('[') {
		var seen_scope = int8(int8(int32(0)))
		var hostspan = string_span_t{(*byte)(func() unsafe.Pointer {
			tempVar := s.s
			return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
		}()), uint32(int32(0))}
		{
			var i = uint32(int32(1))
			for ; i < uint32(s.len); i++ {
				if int32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}()))) == int32('%') {
					if int8(seen_scope) != 0 {
						return int8(int8(int32(0)))
					}
					seen_scope = int8(int8(int32(1)))
					if int8(cNotInt8(is_valid_ipv6(hostspan))) != 0 {
						return int8(int8(int32(0)))
					}
					hostspan = string_span_t{(*byte)(func() unsafe.Pointer {
						tempVar := (*byte)(func() unsafe.Pointer {
							tempVar := s.s
							return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
						}())
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
					}()), uint32(int32(0))}
				} else if int32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}()))) == int32(']') {
					if int8(seen_scope) != 0 {
						if int8(cNotInt8(is_valid_scope(hostspan))) != 0 {
							return int8(int8(int32(0)))
						}
					} else if int8(cNotInt8(is_valid_ipv6(hostspan))) != 0 {
						return int8(int8(int32(0)))
					}
					if i == uint32(s.len)-uint32(uint32(int32(1))) || int32(*((*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i+uint32(uint32(int32(1))))))*unsafe.Sizeof(*tempVar))
					}()))) != int32(':') {
						return int8(int8(int32(0)))
					}
					return is_valid_port(string_span_t{(*byte)(func() unsafe.Pointer {
						tempVar := (*byte)(func() unsafe.Pointer {
							tempVar := s.s
							return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
						}())
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(2))*unsafe.Sizeof(*tempVar))
					}()), uint32(s.len) - i - uint32(uint32(int32(2)))})
				} else {
					hostspan.len += uint32(uint32(int32(1)))
				}
			}
		}
		return int8(int8(int32(0)))
	}
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32(':') {
				var host = string_span_t{s.s, uint32(i)}
				var port = string_span_t{(*byte)(func() unsafe.Pointer {
					tempVar := (*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
					}())
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
				}()), uint32(s.len) - i - uint32(uint32(int32(1)))}
				return int8(int8(func(val bool) int32 {
					if val {
						return 1
					} else {
						return 0
					}
				}(int32(int8(is_valid_port(port))) != 0 && (int32(int8(is_valid_ipv4(host))) != 0 || int32(int8(is_valid_hostname(host))) != 0))))
			}
		}
	}
	return int8(int8(int32(0)))
}

func is_valid_network(s string_span_t) int8 {
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('/') {
				var ip = string_span_t{s.s, uint32(i)}
				var cidr = string_span_t{(*byte)(func() unsafe.Pointer {
					tempVar := (*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
					}())
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
				}()), uint32(s.len) - i - uint32(uint32(int32(1)))}
				var cidrval = uint16(int32(0))
				if uint32(cidr.len) > uint32(uint32(int32(3))) || uint32(cNotUint32(uint32(cidr.len))) != 0 {
					return int8(int8(int32(0)))
				}
				{
					var j = uint32(int32(0))
					for ; j < uint32(cidr.len); j++ {
						if int8(cNotInt8(is_decimal(*((*byte)(func() unsafe.Pointer {
							tempVar := cidr.s
							return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(j)))*unsafe.Sizeof(*tempVar))
						}()))))) != 0 {
							return int8(int8(int32(0)))
						}
						cidrval = uint16(uint16(uint16(int32(10)*int32(uint16(uint16(cidrval))) + int32(*((*byte)(func() unsafe.Pointer {
							tempVar := cidr.s
							return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(j)))*unsafe.Sizeof(*tempVar))
						}()))) - int32('0'))))
					}
				}
				if int8(is_valid_ipv4(ip)) != 0 {
					return int8(int8(func(val bool) int32 {
						if val {
							return 1
						} else {
							return 0
						}
					}(int32(uint16(uint16(cidrval))) <= int32(32))))
				} else if int8(is_valid_ipv6(ip)) != 0 {
					return int8(int8(func(val bool) int32 {
						if val {
							return 1
						} else {
							return 0
						}
					}(int32(uint16(uint16(cidrval))) <= int32(128))))
				}
				return int8(int8(int32(0)))
			}
		}
	}
	return int8(int8(func(val bool) int32 {
		if val {
			return 1
		} else {
			return 0
		}
	}(int32(int8(is_valid_ipv4(s))) != 0 || int32(int8(is_valid_ipv6(s))) != 0)))
}

type field int32

const (
	InterfaceSection    field = 0
	PrivateKey                = 1
	ListenPort                = 2
	Address                   = 3
	DNS                       = 4
	MTU                       = 5
	FwMark                    = 6
	Table                     = 7
	PreUp                     = 8
	PostUp                    = 9
	PreDown                   = 10
	PostDown                  = 11
	SaveConfig                = 12
	PeerSection               = 13
	PublicKey                 = 14
	PresharedKey              = 15
	AllowedIPs                = 16
	Endpoint                  = 17
	PersistentKeepalive       = 18
	Invalid                   = 19
)

func section_for_field(t field) field {
	if uint32(int32(t)) > uint32(int32(InterfaceSection)) && uint32(int32(t)) < uint32(int32(PeerSection)) {
		return InterfaceSection
	}
	if uint32(int32(t)) > uint32(int32(PeerSection)) && uint32(int32(t)) < uint32(int32(Invalid)) {
		return PeerSection
	}
	return Invalid
}

func get_field(s string_span_t) field {
	for {
		if int8(is_caseless_same(s, &[]byte("PrivateKey\x00")[0])) != 0 {
			return PrivateKey
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("ListenPort\x00")[0])) != 0 {
			return ListenPort
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("Address\x00")[0])) != 0 {
			return Address
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("DNS\x00")[0])) != 0 {
			return DNS
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("MTU\x00")[0])) != 0 {
			return MTU
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("PublicKey\x00")[0])) != 0 {
			return PublicKey
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("PresharedKey\x00")[0])) != 0 {
			return PresharedKey
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("AllowedIPs\x00")[0])) != 0 {
			return AllowedIPs
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("Endpoint\x00")[0])) != 0 {
			return Endpoint
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("PersistentKeepalive\x00")[0])) != 0 {
			return PersistentKeepalive
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("FwMark\x00")[0])) != 0 {
			return FwMark
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("Table\x00")[0])) != 0 {
			return Table
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("PreUp\x00")[0])) != 0 {
			return PreUp
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("PostUp\x00")[0])) != 0 {
			return PostUp
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("PreDown\x00")[0])) != 0 {
			return PreDown
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("PostDown\x00")[0])) != 0 {
			return PostDown
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}
	for {
		if int8(is_caseless_same(s, &[]byte("SaveConfig\x00")[0])) != 0 {
			return SaveConfig
		}
		if cNotInt32(int32(0)) != 0 {
			break
		}
	}

	return Invalid
}

func get_sectiontype(s string_span_t) field {
	if int8(is_caseless_same(s, &[]byte("[Peer]\x00")[0])) != 0 {
		return PeerSection
	}
	if int8(is_caseless_same(s, &[]byte("[Interface]\x00")[0])) != 0 {
		return InterfaceSection
	}
	return Invalid
}

type highlight_span_array struct {
	spans *highlightSpan
	len   int
	cap   int
}

func add_to_array(a *highlight_span_array, hs *highlightSpan) {
	slice := *(*[]highlightSpan)(unsafe.Pointer(a))
	slice = append(slice, *hs)
	a.spans = &slice[0]
	a.len = len(slice)
	a.cap = cap(slice)
}

func append_highlight_span(a *highlight_span_array, o *byte, s string_span_t, t highlight) int8 {
	if uint32(cNotUint32(uint32(s.len))) != 0 {
		return int8(int8(int32(1)))
	}
	add_to_array(a, &highlightSpan{t, uint32(int64(uintptr(unsafe.Pointer(s.s))) - int64(uintptr(unsafe.Pointer(o)))), uint32(s.len)})
	return int8(int8(int32(1)))
}

func highlight_multivalue_value(ret *highlight_span_array, parent string_span_t, s string_span_t, section field) {
	switch uint32(int32(section)) {
	case uint32(DNS):
		{
			if int32(int8(is_valid_ipv4(s))) != 0 || int32(int8(is_valid_ipv6(s))) != 0 {
				append_highlight_span(ret, parent.s, s, highlightIP)
			} else if int8(is_valid_hostname(s)) != 0 {
				append_highlight_span(ret, parent.s, s, highlightHost)
			} else {
				append_highlight_span(ret, parent.s, s, highlightError)
			}
		}
	case uint32(Address), uint32(AllowedIPs):
		{
			var slash uint32
			if int8(cNotInt8(is_valid_network(s))) != 0 {
				append_highlight_span(ret, parent.s, s, highlightError)
				break
			}
			for slash = uint32(int32(0)); slash < uint32(s.len); slash++ {
				if int32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(slash)))*unsafe.Sizeof(*tempVar))
				}()))) == int32('/') {
					break
				}
			}
			if slash == uint32(s.len) {
				append_highlight_span(ret, parent.s, s, highlightIP)
			} else {
				append_highlight_span(ret, parent.s, string_span_t{s.s, uint32(slash)}, highlightIP)
				append_highlight_span(ret, parent.s, string_span_t{(*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(slash)))*unsafe.Sizeof(*tempVar))
				}()), uint32(int32(1))}, highlightDelimiter)
				append_highlight_span(ret, parent.s, string_span_t{(*byte)(func() unsafe.Pointer {
					tempVar := (*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(slash)))*unsafe.Sizeof(*tempVar))
					}())
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
				}()), uint32(s.len) - slash - uint32(uint32(int32(1)))}, highlightCidr)
			}
		}
	default:
		{
			append_highlight_span(ret, parent.s, s, highlightError)
		}
	}
}

func highlight_multivalue(ret *highlight_span_array, parent string_span_t, s string_span_t, section field) {
	var current_span = string_span_t{s.s, uint32(int32(0))}
	var len_at_last_space = uint32(int32(0))
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32(',') {
				current_span.len = len_at_last_space
				highlight_multivalue_value(ret, string_span_t(parent), string_span_t(current_span), section)
				append_highlight_span(ret, parent.s, string_span_t{(*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}()), uint32(int32(1))}, highlightDelimiter)
				len_at_last_space = uint32(int32(0))
				current_span = string_span_t{(*byte)(func() unsafe.Pointer {
					tempVar := (*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
					}())
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
				}()), uint32(int32(0))}
			} else if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32(' ') || int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('\t') {
				if int64(uintptr(unsafe.Pointer(&*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}()))))) == int64(uintptr(unsafe.Pointer(current_span.s))) && uint32(cNotUint32(uint32(current_span.len))) != 0 {
					current_span.s = (*byte)(func() unsafe.Pointer {
						tempVar := current_span.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(1)*unsafe.Sizeof(*tempVar))
					}())
				} else {
					current_span.len += uint32(uint32(int32(1)))
				}
			} else {
				len_at_last_space = func() uint32 {
					tempVar := &current_span.len
					*tempVar += 1
					return *tempVar
				}()
			}
		}
	}
	current_span.len = len_at_last_space
	if uint32(uint32(current_span.len)) != 0 {
		highlight_multivalue_value(ret, string_span_t(parent), string_span_t(current_span), section)
	} else if uint32(int32((*((*highlightSpan)(func() unsafe.Pointer {
		tempVar := (*ret).spans
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(uint32((*ret).len)-uint32(uint32(int32(1))))))*unsafe.Sizeof(*tempVar))
	}()))).t)) == uint32(int32(highlightDelimiter)) {
		(*((*highlightSpan)(func() unsafe.Pointer {
			tempVar := (*ret).spans
			return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(uint32((*ret).len)-uint32(uint32(int32(1))))))*unsafe.Sizeof(*tempVar))
		}()))).t = highlightError
	}
}

func highlight_value(ret *highlight_span_array, parent string_span_t, s string_span_t, section field) {
	switch uint32(int32(section)) {
	case uint32(PrivateKey):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_key(s))) != 0 {
					return int32(highlightPrivateKey)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(PublicKey):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_key(s))) != 0 {
					return int32(highlightPublicKey)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(PresharedKey):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_key(s))) != 0 {
					return int32(highlightPresharedKey)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(MTU):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_mtu(s))) != 0 {
					return int32(highlightMTU)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(SaveConfig):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_saveconfig(s))) != 0 {
					return int32(highlightSaveConfig)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(FwMark):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_fwmark(s))) != 0 {
					return int32(highlightFwMark)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(Table):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_table(s))) != 0 {
					return int32(highlightTable)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(PreUp), uint32(PostUp), uint32(PreDown), uint32(PostDown):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_prepostupdown(s))) != 0 {
					return int32(highlightCmd)
				} else {
					return int32(highlightError)
				}
			}()))
		}

	case uint32(ListenPort):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_port(s))) != 0 {
					return int32(highlightPort)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(PersistentKeepalive):
		{
			append_highlight_span(ret, parent.s, s, highlight(func() int32 {
				if int32(int8(is_valid_persistentkeepalive(s))) != 0 {
					return int32(highlightKeepalive)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(Endpoint):
		{
			var colon uint32
			if int8(cNotInt8(is_valid_endpoint(s))) != 0 {
				append_highlight_span(ret, parent.s, s, highlightError)
				break
			}
			for colon = uint32(s.len); func() uint32 {
				defer func() {
					colon -= 1
				}()
				return colon
			}() > uint32(uint32(int32(0))); {
				if int32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(colon)))*unsafe.Sizeof(*tempVar))
				}()))) == int32(':') {
					break
				}
			}
			append_highlight_span(ret, parent.s, string_span_t{s.s, uint32(colon)}, highlightHost)
			append_highlight_span(ret, parent.s, string_span_t{(*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(colon)))*unsafe.Sizeof(*tempVar))
			}()), uint32(int32(1))}, highlightDelimiter)
			append_highlight_span(ret, parent.s, string_span_t{(*byte)(func() unsafe.Pointer {
				tempVar := (*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(colon)))*unsafe.Sizeof(*tempVar))
				}())
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
			}()), uint32(s.len) - colon - uint32(uint32(int32(1)))}, highlightPort)
		}
	case uint32(Address), uint32(DNS), uint32(AllowedIPs):
		{
			highlight_multivalue(ret, string_span_t(parent), string_span_t(s), section)
		}
	default:
		{
			append_highlight_span(ret, parent.s, s, highlightError)
		}
	}
}

type parser_state int32

const (
	OnNone    parser_state = 0
	OnKey                  = 1
	OnValue                = 2
	OnComment              = 3
	OnSection              = 4
)

func highlight_config(config *byte) []highlightSpan {
	var ret highlight_span_array
	var s = string_span_t{config, uint32(uint32(cStrlen(config)))}
	var current_span = string_span_t{s.s, uint32(int32(0))}
	var current_section field = Invalid
	var current_field field = Invalid
	var state = OnNone
	var len_at_last_space = uint32(int32(0))
	var equals_location = uint32(int32(0))
	{
		var i = uint32(int32(0))
		for ; i <= uint32(s.len); i++ {
			if i == uint32(s.len) || int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('\n') || uint32(int32(state)) != uint32(int32(OnComment)) && int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('#') {
				if uint32(int32(state)) == uint32(int32(OnKey)) {
					current_span.len = len_at_last_space
					append_highlight_span(&ret, s.s, current_span, highlightError)
				} else if uint32(int32(state)) == uint32(int32(OnValue)) {
					if uint32(uint32(current_span.len)) != 0 {
						append_highlight_span(&ret, s.s, string_span_t{(*byte)(func() unsafe.Pointer {
							tempVar := s.s
							return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(equals_location)))*unsafe.Sizeof(*tempVar))
						}()), uint32(int32(1))}, highlightDelimiter)
						current_span.len = len_at_last_space
						highlight_value(&ret, string_span_t(s), string_span_t(current_span), current_field)
					} else {
						append_highlight_span(&ret, s.s, string_span_t{(*byte)(func() unsafe.Pointer {
							tempVar := s.s
							return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(equals_location)))*unsafe.Sizeof(*tempVar))
						}()), uint32(int32(1))}, highlightError)
					}
				} else if uint32(int32(state)) == uint32(int32(OnSection)) {
					current_span.len = len_at_last_space
					current_section = get_sectiontype(current_span)
					append_highlight_span(&ret, s.s, current_span, highlight(func() int32 {
						if uint32(int32(current_section)) == uint32(int32(Invalid)) {
							return int32(highlightError)
						} else {
							return int32(highlightSection)
						}
					}()))
				} else if uint32(int32(state)) == uint32(int32(OnComment)) {
					append_highlight_span(&ret, s.s, current_span, highlightComment)
				}
				if i == uint32(s.len) {
					break
				}
				len_at_last_space = uint32(int32(0))
				current_field = Invalid
				if int32(*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}()))) == int32('#') {
					current_span = string_span_t{(*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
					}()), uint32(int32(1))}
					state = OnComment
				} else {
					current_span = string_span_t{(*byte)(func() unsafe.Pointer {
						tempVar := (*byte)(func() unsafe.Pointer {
							tempVar := s.s
							return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
						}())
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
					}()), uint32(int32(0))}
					state = OnNone
				}
			} else if uint32(int32(state)) == uint32(int32(OnComment)) {
				current_span.len += uint32(uint32(int32(1)))
			} else if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32(' ') || int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('\t') {
				if int64(uintptr(unsafe.Pointer(&*((*byte)(func() unsafe.Pointer {
					tempVar := s.s
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
				}()))))) == int64(uintptr(unsafe.Pointer(current_span.s))) && uint32(cNotUint32(uint32(current_span.len))) != 0 {
					current_span.s = (*byte)(func() unsafe.Pointer {
						tempVar := current_span.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(1)*unsafe.Sizeof(*tempVar))
					}())
				} else {
					current_span.len += uint32(uint32(int32(1)))
				}
			} else if int32(*((*byte)(func() unsafe.Pointer {
				tempVar := s.s
				return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
			}()))) == int32('=') && uint32(int32(state)) == uint32(int32(OnKey)) {
				current_span.len = len_at_last_space
				current_field = get_field(current_span)
				var section = section_for_field(current_field)
				if uint32(int32(section)) == uint32(int32(Invalid)) || uint32(int32(current_field)) == uint32(int32(Invalid)) || uint32(int32(section)) != uint32(int32(current_section)) {
					append_highlight_span(&ret, s.s, current_span, highlightError)
				} else {
					append_highlight_span(&ret, s.s, current_span, highlightField)
				}
				equals_location = i
				current_span = string_span_t{(*byte)(func() unsafe.Pointer {
					tempVar := (*byte)(func() unsafe.Pointer {
						tempVar := s.s
						return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
					}())
					return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(1))*unsafe.Sizeof(*tempVar))
				}()), uint32(int32(0))}
				state = OnValue
			} else {
				if uint32(int32(state)) == uint32(int32(OnNone)) {
					state = parser_state(func() int32 {
						if int32(*((*byte)(func() unsafe.Pointer {
							tempVar := s.s
							return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*tempVar))
						}()))) == int32('[') {
							return int32(OnSection)
						} else {
							return int32(OnKey)
						}
					}())
				}
				len_at_last_space = func() uint32 {
					tempVar := &current_span.len
					*tempVar += 1
					return *tempVar
				}()
			}
		}
	}
	return *(*[]highlightSpan)(unsafe.Pointer(&ret))
}

func highlightConfig(config string) []highlightSpan {
	return highlight_config(&append([]byte(config), 0)[0])
}
