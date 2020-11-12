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

func at(a *byte, i uint32) *byte {
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(a)) + uintptr(i)*unsafe.Sizeof(*a)))
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

type stringSpan struct {
	s   *byte
	len uint32
}

func isDecimal(c byte) bool {
	return int32(c) >= int32('0') && int32(c) <= int32('9')
}

func isHexadecimal(c byte) bool {
	return isDecimal(c) || (int32(c)|int32(32)) >= int32('a') && (int32(c)|int32(32)) <= int32('f')
}

func isAlphabet(c byte) bool {
	return (int32(c)|int32(32)) >= int32('a') && (int32(c)|int32(32)) <= int32('z')
}

func isSame(s stringSpan, c *byte) bool {
	var len = uint32(uint32(cStrlen(c)))
	if len != uint32(s.len) {
		return false
	}
	return cMemcmp(unsafe.Pointer(s.s), unsafe.Pointer(c), int32(uint32(uint32(len)))) == 0
}

func isCaselessSame(s stringSpan, c *byte) bool {
	var len = uint32(uint32(cStrlen(c)))
	if len != uint32(s.len) {
		return false
	}
	{
		var i = uint32(int32(0))
		for ; i < len; i++ {
			var a = *((*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(c)) + (uintptr)(int32(uint32(i)))*unsafe.Sizeof(*c))))
			var b = *at(s.s, i)
			if uint32(a)-uint32('a') < uint32(int32(26)) {
				a &= byte(byte(int32(95)))
			}
			if uint32(b)-uint32('a') < uint32(int32(26)) {
				b &= byte(byte(int32(95)))
			}
			if int32(a) != int32(b) {
				return false
			}
		}
	}
	return true
}

func isValidKey(s stringSpan) bool {
	if uint32(s.len) != uint32(uint32(int32(44))) || int32(*at(s.s, 43)) != int32('=') {
		return false
	}
	{
		var i = uint32(int32(0))
		for ; i < uint32(uint32(int32(42))); i++ {
			if !isDecimal(*at(s.s, i)) && !isAlphabet(*at(s.s, i)) && int32(*at(s.s, i)) != int32('/') && int32(*at(s.s, i)) != int32('+') {
				return false
			}
		}
	}
	switch int32(*at(s.s, 42)) {
	case 'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '4', '8', '0':
		{
		}
	default:
		{
			return false
		}
	}
	return true
}

func isValidHostname(s stringSpan) bool {
	var num_digit = uint32(int32(0))
	var num_entity = uint32(s.len)
	if uint32(s.len) > uint32(uint32(int32(63))) || s.len == 0 {
		return false
	}
	if int32(*s.s) == int32('-') || int32(*at(s.s, uint32(uint32(s.len)-uint32(uint32(int32(1)))))) == int32('-') {
		return false
	}
	if int32(*s.s) == int32('.') || int32(*at(s.s, uint32(uint32(s.len)-uint32(uint32(int32(1)))))) == int32('.') {
		return false
	}
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if isDecimal(*at(s.s, i)) {
				num_digit += 1
				continue
			}
			if int32(*at(s.s, i)) == int32('.') {
				num_entity -= 1
				continue
			}
			if !isAlphabet(*at(s.s, i)) && int32(*at(s.s, i)) != int32('-') {
				return false
			}
			if uint32(i) != 0 && int32(*at(s.s, i)) == int32('.') && int32(*at(s.s, uint32(i-uint32(uint32(int32(1)))))) == int32('.') {
				return false
			}
		}
	}
	return num_digit != num_entity
}

func isValidIPv4(s stringSpan) bool {
	{
		var j uint32
		var i = uint32(int32(0))
		var pos = uint32(int32(0))
		for ; i < uint32(uint32(int32(4))) && pos < uint32(s.len); i++ {
			var val = uint32(int32(0))
			for j = uint32(int32(0)); j < uint32(uint32(int32(3))) && pos+j < uint32(s.len) && isDecimal(*at(s.s, pos+j)); j++ {
				val = uint32(uint32(uint32(int32(10))*uint32(uint32(val)) + uint32(*at(s.s, pos+j)) - uint32('0')))
			}
			if j == uint32(uint32(int32(0))) || j > uint32(uint32(int32(1))) && int32(*at(s.s, pos)) == int32('0') || val > uint32(uint32(uint32(int32(255)))) {
				return false
			}
			if pos+j == uint32(s.len) && i == uint32(uint32(int32(3))) {
				return true
			}
			if int32(*at(s.s, pos+j)) != int32('.') {
				return false
			}
			pos += j + uint32(uint32(int32(1)))
		}
	}
	return false
}

func isValidIPv6(s stringSpan) bool {
	var pos = uint32(int32(0))
	var seenColon = false
	if uint32(s.len) < uint32(uint32(int32(2))) {
		return false
	}
	if int32(*at(s.s, pos)) == int32(':') && int32(*at(s.s, func() uint32 {
		pos += 1
		return pos
	}())) != int32(':') {
		return false
	}
	if int32(*at(s.s, uint32(uint32(s.len)-uint32(uint32(int32(1)))))) == int32(':') && int32(*at(s.s, uint32(uint32(s.len)-uint32(uint32(int32(2)))))) != int32(':') {
		return false
	}
	{
		var j uint32
		var i = uint32(int32(0))
		for ; pos < uint32(s.len); i++ {
			if int32(*at(s.s, pos)) == int32(':') && !seenColon {
				seenColon = true
				if func() uint32 {
					pos += 1
					return pos
				}() == uint32(s.len) {
					break
				}
				if i == uint32(uint32(int32(7))) {
					return false
				}
				continue
			}
			for j = uint32(int32(0)); ; j++ {
				if j < uint32(uint32(int32(4))) && pos+j < uint32(s.len) && isHexadecimal(*at(s.s, pos+j)) {
					continue
				}
				break
			}
			if j == uint32(uint32(int32(0))) {
				return false
			}
			if pos+j == uint32(s.len) && (seenColon || i == uint32(uint32(int32(7)))) {
				break
			}
			if i == uint32(uint32(int32(7))) {
				return false
			}
			if int32(*at(s.s, pos+j)) != int32(':') {
				if int32(*at(s.s, pos+j)) != int32('.') || i < uint32(uint32(int32(6))) && !seenColon {
					return false
				}
				return isValidIPv4(stringSpan{at(s.s, pos), uint32(s.len) - pos})
			}
			pos += j + uint32(uint32(int32(1)))
		}
	}
	return true
}

/* Bound this around 32 bits, so that we don't have to write overflow logic. */
func isValidUint(s stringSpan, support_hex bool, min uint64, max uint64) bool {
	var val = uint64(int32(0))
	if uint32(s.len) > uint32(uint32(int32(10))) || s.len == 0 {
		return false
	}
	if support_hex && uint32(s.len) > uint32(uint32(int32(2))) && int32(*s.s) == int32('0') && int32(*at(s.s, 1)) == int32('x') {
		{
			var i = uint32(int32(2))
			for ; i < uint32(s.len); i++ {
				if uint32(*at(s.s, i))-uint32('0') < uint32(int32(10)) {
					val = uint64(uint64(uint32(int32(16))*uint32(uint64(val)) + uint32(int32(*at(s.s, i))-int32('0'))))
				} else if uint32(*at(s.s, i))|uint32(int32(32))-uint32('a') < uint32(int32(6)) {
					val = uint64(uint64(uint32(int32(16))*uint32(uint64(val)) + uint32(int32(*at(s.s, i))|int32(32)) - uint32('a') + uint32(int32(10))))
				} else {
					return false
				}
			}
		}
	} else {
		{
			var i = uint32(int32(0))
			for ; i < uint32(s.len); i++ {
				if !isDecimal(*at(s.s, i)) {
					return false
				}
				val = uint64(uint64(uint32(int32(10))*uint32(uint64(val)) + uint32(*at(s.s, i)) - uint32('0')))
			}
		}
	}
	return val <= max && val >= min
}

func isValidPort(s stringSpan) bool {
	return isValidUint(s, false, uint64(int32(0)), uint64(int32(65535)))
}

func isValidMTU(s stringSpan) bool {
	return isValidUint(s, false, uint64(int32(576)), uint64(int32(65535)))
}

func isValidPersistentKeepAlive(s stringSpan) bool {
	if isSame(s, &[]byte("off\x00")[0]) {
		return true
	}
	return isValidUint(s, false, uint64(int32(0)), uint64(int32(65535)))
}

func isValidFwMark(s stringSpan) bool {
	if isSame(s, &[]byte("off\x00")[0]) {
		return true
	}
	return isValidUint(s, true, uint64(int32(0)), uint64(4294967295))
}

/* This pretty much invalidates the other checks, but rt_names.c's
 * fread_id_name does no validation aside from this. */
func isValidTable(s stringSpan) bool {
	if isSame(s, &[]byte("auto\x00")[0]) {
		return true
	}
	if isSame(s, &[]byte("off\x00")[0]) {
		return true
	}
	if uint32(s.len) < uint32(uint32(int32(512))) {
		return true
	}
	return isValidUint(s, false, uint64(int32(0)), uint64(4294967295))
}

func isValidSaveConfig(s stringSpan) bool {
	return isSame(s, &[]byte("true\x00")[0]) || isSame(s, &[]byte("false\x00")[0])
}

/* It's probably not worthwhile to try to validate a bash expression.
 * So instead we just demand non-zero length. */
func isValidPrePostUpDown(s stringSpan) bool {
	return s.len != 0
}

func isValidScope(s stringSpan) bool {
	if uint32(s.len) > uint32(uint32(int32(64))) || s.len == 0 {
		return false
	}
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if isAlphabet(*at(s.s, i)) && !isDecimal(*at(s.s, i)) && int32(*at(s.s, i)) != int32('_') && int32(*at(s.s, i)) != int32('=') && int32(*at(s.s, i)) != int32('+') && int32(*at(s.s, i)) != int32('.') && int32(*at(s.s, i)) != int32('-') {
				return false
			}
		}
	}
	return true
}

func isValidEndpoint(s stringSpan) bool {
	if s.len == 0 {
		return false
	}
	if int32(*s.s) == int32('[') {
		var seenScope = false
		var hostspan = stringSpan{at(s.s, 1), uint32(int32(0))}
		{
			var i = uint32(int32(1))
			for ; i < uint32(s.len); i++ {
				if int32(*at(s.s, i)) == int32('%') {
					if seenScope {
						return false
					}
					seenScope = true
					if !isValidIPv6(hostspan) {
						return false
					}
					hostspan = stringSpan{at(s.s, i+1), uint32(int32(0))}
				} else if int32(*at(s.s, i)) == int32(']') {
					if seenScope {
						if !isValidScope(hostspan) {
							return false
						}
					} else if !isValidIPv6(hostspan) {
						return false
					}
					if i == uint32(s.len)-uint32(uint32(int32(1))) || int32(*at(s.s, uint32(i+uint32(uint32(int32(1)))))) != int32(':') {
						return false
					}
					return isValidPort(stringSpan{at(s.s, i+2), uint32(s.len) - i - uint32(uint32(int32(2)))})
				} else {
					hostspan.len += uint32(uint32(int32(1)))
				}
			}
		}
		return false
	}
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if int32(*at(s.s, i)) == int32(':') {
				var host = stringSpan{s.s, uint32(i)}
				var port = stringSpan{at(s.s, i+1), uint32(s.len) - i - uint32(uint32(int32(1)))}
				return isValidPort(port) && (isValidIPv4(host) || isValidHostname(host))
			}
		}
	}
	return false
}

func isValidNetwork(s stringSpan) bool {
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if int32(*at(s.s, i)) == int32('/') {
				var ip = stringSpan{s.s, uint32(i)}
				var cidr = stringSpan{at(s.s, i+1), uint32(s.len) - i - uint32(uint32(int32(1)))}
				var cidrval = uint16(int32(0))
				if uint32(cidr.len) > uint32(uint32(int32(3))) || cidr.len == 0 {
					return false
				}
				{
					var j = uint32(int32(0))
					for ; j < uint32(cidr.len); j++ {
						if !isDecimal(*at(cidr.s, j)) {
							return false
						}
						cidrval = uint16(uint16(uint16(int32(10)*int32(uint16(uint16(cidrval))) + int32(*at(cidr.s, j)) - int32('0'))))
					}
				}
				if isValidIPv4(ip) {
					return int32(uint16(uint16(cidrval))) <= int32(32)
				} else if isValidIPv6(ip) {
					return int32(uint16(uint16(cidrval))) <= int32(128)
				}
				return false
			}
		}
	}
	return isValidIPv4(s) || isValidIPv6(s)
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

func sectionForField(t field) field {
	if uint32(int32(t)) > uint32(int32(InterfaceSection)) && uint32(int32(t)) < uint32(int32(PeerSection)) {
		return InterfaceSection
	}
	if uint32(int32(t)) > uint32(int32(PeerSection)) && uint32(int32(t)) < uint32(int32(Invalid)) {
		return PeerSection
	}
	return Invalid
}

func getField(s stringSpan) field {
	switch {
	case isCaselessSame(s, &[]byte("PrivateKey\x00")[0]):
		return PrivateKey
	case isCaselessSame(s, &[]byte("ListenPort\x00")[0]):
		return ListenPort
	case isCaselessSame(s, &[]byte("Address\x00")[0]):
		return Address
	case isCaselessSame(s, &[]byte("DNS\x00")[0]):
		return DNS
	case isCaselessSame(s, &[]byte("MTU\x00")[0]):
		return MTU
	case isCaselessSame(s, &[]byte("PublicKey\x00")[0]):
		return PublicKey
	case isCaselessSame(s, &[]byte("PresharedKey\x00")[0]):
		return PresharedKey
	case isCaselessSame(s, &[]byte("AllowedIPs\x00")[0]):
		return AllowedIPs
	case isCaselessSame(s, &[]byte("Endpoint\x00")[0]):
		return Endpoint
	case isCaselessSame(s, &[]byte("PersistentKeepalive\x00")[0]):
		return PersistentKeepalive
	case isCaselessSame(s, &[]byte("FwMark\x00")[0]):
		return FwMark
	case isCaselessSame(s, &[]byte("Table\x00")[0]):
		return Table
	case isCaselessSame(s, &[]byte("PreUp\x00")[0]):
		return PreUp
	case isCaselessSame(s, &[]byte("PostUp\x00")[0]):
		return PostUp
	case isCaselessSame(s, &[]byte("PreDown\x00")[0]):
		return PreDown
	case isCaselessSame(s, &[]byte("PostDown\x00")[0]):
		return PostDown
	case isCaselessSame(s, &[]byte("SaveConfig\x00")[0]):
		return SaveConfig
	}
	return Invalid
}

func getSectionType(s stringSpan) field {
	switch {
	case isCaselessSame(s, &[]byte("[Peer]\x00")[0]):
		return PeerSection
	case isCaselessSame(s, &[]byte("[Interface]\x00")[0]):
		return InterfaceSection
	}
	return Invalid
}

type highlightSpanArray struct {
	spans *highlightSpan
	len   int
	cap   int
}

func addToArray(a *highlightSpanArray, hs *highlightSpan) {
	slice := *(*[]highlightSpan)(unsafe.Pointer(a))
	slice = append(slice, *hs)
	a.spans = &slice[0]
	a.len = len(slice)
	a.cap = cap(slice)
}

func appendHighlightSpan(a *highlightSpanArray, o *byte, s stringSpan, t highlight) bool {
	if s.len == 0 {
		return true
	}
	addToArray(a, &highlightSpan{t, uint32(int64(uintptr(unsafe.Pointer(s.s))) - int64(uintptr(unsafe.Pointer(o)))), uint32(s.len)})
	return true
}

func highlightMultivalueValue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	switch uint32(int32(section)) {
	case uint32(DNS):
		{
			if isValidIPv4(s) || isValidIPv6(s) {
				appendHighlightSpan(ret, parent.s, s, highlightIP)
			} else if isValidHostname(s) {
				appendHighlightSpan(ret, parent.s, s, highlightHost)
			} else {
				appendHighlightSpan(ret, parent.s, s, highlightError)
			}
		}
	case uint32(Address), uint32(AllowedIPs):
		{
			var slash uint32
			if !isValidNetwork(s) {
				appendHighlightSpan(ret, parent.s, s, highlightError)
				break
			}
			for slash = uint32(int32(0)); slash < uint32(s.len); slash++ {
				if int32(*at(s.s, slash)) == int32('/') {
					break
				}
			}
			if slash == uint32(s.len) {
				appendHighlightSpan(ret, parent.s, s, highlightIP)
			} else {
				appendHighlightSpan(ret, parent.s, stringSpan{s.s, uint32(slash)}, highlightIP)
				appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, slash), uint32(int32(1))}, highlightDelimiter)
				appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, slash+1), uint32(s.len) - slash - uint32(uint32(int32(1)))}, highlightCidr)
			}
		}
	default:
		{
			appendHighlightSpan(ret, parent.s, s, highlightError)
		}
	}
}

func highlightMultivalue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	var currentSpan = stringSpan{s.s, uint32(int32(0))}
	var lenAtLastSpace = uint32(int32(0))
	{
		var i = uint32(int32(0))
		for ; i < uint32(s.len); i++ {
			if int32(*at(s.s, i)) == int32(',') {
				currentSpan.len = lenAtLastSpace
				highlightMultivalueValue(ret, stringSpan(parent), stringSpan(currentSpan), section)
				appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, i), uint32(int32(1))}, highlightDelimiter)
				lenAtLastSpace = uint32(int32(0))
				currentSpan = stringSpan{at(s.s, i+1), uint32(int32(0))}
			} else if int32(*at(s.s, i)) == int32(' ') || int32(*at(s.s, i)) == int32('\t') {
				if int64(uintptr(unsafe.Pointer(&*at(s.s, i)))) == int64(uintptr(unsafe.Pointer(currentSpan.s))) && currentSpan.len == 0 {
					currentSpan.s = at(currentSpan.s, 1)
				} else {
					currentSpan.len += uint32(uint32(int32(1)))
				}
			} else {
				lenAtLastSpace = func() uint32 {
					tempVar := &currentSpan.len
					*tempVar += 1
					return *tempVar
				}()
			}
		}
	}
	currentSpan.len = lenAtLastSpace
	if uint32(uint32(currentSpan.len)) != 0 {
		highlightMultivalueValue(ret, stringSpan(parent), stringSpan(currentSpan), section)
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

func highlightValue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	switch uint32(int32(section)) {
	case uint32(PrivateKey):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidKey(s) {
					return int32(highlightPrivateKey)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(PublicKey):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidKey(s) {
					return int32(highlightPublicKey)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(PresharedKey):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidKey(s) {
					return int32(highlightPresharedKey)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(MTU):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidMTU(s) {
					return int32(highlightMTU)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(SaveConfig):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidSaveConfig(s) {
					return int32(highlightSaveConfig)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(FwMark):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidFwMark(s) {
					return int32(highlightFwMark)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(Table):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidTable(s) {
					return int32(highlightTable)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(PreUp), uint32(PostUp), uint32(PreDown), uint32(PostDown):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidPrePostUpDown(s) {
					return int32(highlightCmd)
				} else {
					return int32(highlightError)
				}
			}()))
		}

	case uint32(ListenPort):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidPort(s) {
					return int32(highlightPort)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(PersistentKeepalive):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidPersistentKeepAlive(s) {
					return int32(highlightKeepalive)
				} else {
					return int32(highlightError)
				}
			}()))
		}
	case uint32(Endpoint):
		{
			var colon uint32
			if !isValidEndpoint(s) {
				appendHighlightSpan(ret, parent.s, s, highlightError)
				break
			}
			for colon = uint32(s.len); func() uint32 {
				defer func() {
					colon -= 1
				}()
				return colon
			}() > uint32(uint32(int32(0))); {
				if int32(*at(s.s, colon)) == int32(':') {
					break
				}
			}
			appendHighlightSpan(ret, parent.s, stringSpan{s.s, uint32(colon)}, highlightHost)
			appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, colon), uint32(int32(1))}, highlightDelimiter)
			appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, colon+1), uint32(s.len) - colon - uint32(uint32(int32(1)))}, highlightPort)
		}
	case uint32(Address), uint32(DNS), uint32(AllowedIPs):
		{
			highlightMultivalue(ret, stringSpan(parent), stringSpan(s), section)
		}
	default:
		{
			appendHighlightSpan(ret, parent.s, s, highlightError)
		}
	}
}

type parserState int32

const (
	OnNone    parserState = 0
	OnKey                 = 1
	OnValue               = 2
	OnComment             = 3
	OnSection             = 4
)

func highlightConfigInt(config *byte) []highlightSpan {
	var ret highlightSpanArray
	var s = stringSpan{config, uint32(uint32(cStrlen(config)))}
	var currentSpan = stringSpan{s.s, uint32(int32(0))}
	var currentSection field = Invalid
	var currentField field = Invalid
	var state = OnNone
	var lenAtLastSpace = uint32(int32(0))
	var equalsLocation = uint32(int32(0))
	{
		var i = uint32(int32(0))
		for ; i <= uint32(s.len); i++ {
			if i == uint32(s.len) || int32(*at(s.s, i)) == int32('\n') || uint32(int32(state)) != uint32(int32(OnComment)) && int32(*at(s.s, i)) == int32('#') {
				if uint32(int32(state)) == uint32(int32(OnKey)) {
					currentSpan.len = lenAtLastSpace
					appendHighlightSpan(&ret, s.s, currentSpan, highlightError)
				} else if uint32(int32(state)) == uint32(int32(OnValue)) {
					if uint32(uint32(currentSpan.len)) != 0 {
						appendHighlightSpan(&ret, s.s, stringSpan{at(s.s, equalsLocation), uint32(int32(1))}, highlightDelimiter)
						currentSpan.len = lenAtLastSpace
						highlightValue(&ret, stringSpan(s), stringSpan(currentSpan), currentField)
					} else {
						appendHighlightSpan(&ret, s.s, stringSpan{at(s.s, equalsLocation), uint32(int32(1))}, highlightError)
					}
				} else if uint32(int32(state)) == uint32(int32(OnSection)) {
					currentSpan.len = lenAtLastSpace
					currentSection = getSectionType(currentSpan)
					appendHighlightSpan(&ret, s.s, currentSpan, highlight(func() int32 {
						if uint32(int32(currentSection)) == uint32(int32(Invalid)) {
							return int32(highlightError)
						} else {
							return int32(highlightSection)
						}
					}()))
				} else if uint32(int32(state)) == uint32(int32(OnComment)) {
					appendHighlightSpan(&ret, s.s, currentSpan, highlightComment)
				}
				if i == uint32(s.len) {
					break
				}
				lenAtLastSpace = uint32(int32(0))
				currentField = Invalid
				if int32(*at(s.s, i)) == int32('#') {
					currentSpan = stringSpan{at(s.s, i), uint32(int32(1))}
					state = OnComment
				} else {
					currentSpan = stringSpan{at(s.s, i+1), uint32(int32(0))}
					state = OnNone
				}
			} else if uint32(int32(state)) == uint32(int32(OnComment)) {
				currentSpan.len += uint32(uint32(int32(1)))
			} else if int32(*at(s.s, i)) == int32(' ') || int32(*at(s.s, i)) == int32('\t') {
				if int64(uintptr(unsafe.Pointer(&*at(s.s, i)))) == int64(uintptr(unsafe.Pointer(currentSpan.s))) && currentSpan.len == 0 {
					currentSpan.s = at(currentSpan.s, 1)
				} else {
					currentSpan.len += uint32(uint32(int32(1)))
				}
			} else if int32(*at(s.s, i)) == int32('=') && uint32(int32(state)) == uint32(int32(OnKey)) {
				currentSpan.len = lenAtLastSpace
				currentField = getField(currentSpan)
				var section = sectionForField(currentField)
				if uint32(int32(section)) == uint32(int32(Invalid)) || uint32(int32(currentField)) == uint32(int32(Invalid)) || uint32(int32(section)) != uint32(int32(currentSection)) {
					appendHighlightSpan(&ret, s.s, currentSpan, highlightError)
				} else {
					appendHighlightSpan(&ret, s.s, currentSpan, highlightField)
				}
				equalsLocation = i
				currentSpan = stringSpan{at(s.s, i+1), uint32(int32(0))}
				state = OnValue
			} else {
				if uint32(int32(state)) == uint32(int32(OnNone)) {
					state = parserState(func() int32 {
						if int32(*at(s.s, i)) == int32('[') {
							return int32(OnSection)
						} else {
							return int32(OnKey)
						}
					}())
				}
				lenAtLastSpace = func() uint32 {
					tempVar := &currentSpan.len
					*tempVar += 1
					return *tempVar
				}()
			}
		}
	}
	return *(*[]highlightSpan)(unsafe.Pointer(&ret))
}

func highlightConfig(config string) []highlightSpan {
	return highlightConfigInt(&append([]byte(config), 0)[0])
}
