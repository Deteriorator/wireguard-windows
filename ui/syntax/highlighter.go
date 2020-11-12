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

func toByteSlice(a *byte, length int) []byte {
	header := struct {
		ptr unsafe.Pointer
		len int
		cap int
	}{
		unsafe.Pointer(a),
		length,
		length,
	}
	return (*(*[]byte)(unsafe.Pointer(&header)))[:]
}

func cStrlen(a *byte) int {
	for i := 0; ; i++ {
		if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(a)) + uintptr(i))) == 0 {
			return i
		}
	}
}

func cMemcmp(src1, src2 unsafe.Pointer, n int) int {
	b1 := toByteSlice((*byte)(src1), n)
	b2 := toByteSlice((*byte)(src2), n)
	return (bytes.Compare(b1, b2))
}

func at(a *byte, i int) *byte {
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(a)) + uintptr(i)*unsafe.Sizeof(*a)))
}

type highlight int

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
	s   int
	len int
}

type stringSpan struct {
	s   *byte
	len int
}

func isDecimal(c byte) bool {
	return (c) >= ('0') && (c) <= ('9')
}

func isHexadecimal(c byte) bool {
	return isDecimal(c) || ((c)|(32)) >= ('a') && ((c)|(32)) <= ('f')
}

func isAlphabet(c byte) bool {
	return ((c)|(32)) >= ('a') && ((c)|(32)) <= ('z')
}

func isSame(s stringSpan, c *byte) bool {
	var len = (cStrlen(c))
	if len != (s.len) {
		return false
	}
	return cMemcmp(unsafe.Pointer(s.s), unsafe.Pointer(c), (len)) == 0
}

func isCaselessSame(s stringSpan, c *byte) bool {
	var len = (cStrlen(c))
	if len != (s.len) {
		return false
	}
	{
		var i = (0)
		for ; i < len; i++ {
			var a = *at(c, i)
			var b = *at(s.s, i)
			if (a)-('a') < (26) {
				a &= (95)
			}
			if (b)-('a') < (26) {
				b &= (95)
			}
			if (a) != (b) {
				return false
			}
		}
	}
	return true
}

func isValidKey(s stringSpan) bool {
	if (s.len) != (44) || (*at(s.s, 43)) != ('=') {
		return false
	}
	{
		var i = (0)
		for ; i < (42); i++ {
			if !isDecimal(*at(s.s, i)) && !isAlphabet(*at(s.s, i)) && (*at(s.s, i)) != ('/') && (*at(s.s, i)) != ('+') {
				return false
			}
		}
	}
	switch *at(s.s, 42) {
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
	var num_digit = (0)
	var num_entity = (s.len)
	if (s.len) > (63) || s.len == 0 {
		return false
	}
	if (*s.s) == ('-') || (*at(s.s, ((s.len) - (1)))) == ('-') {
		return false
	}
	if (*s.s) == ('.') || (*at(s.s, ((s.len) - (1)))) == ('.') {
		return false
	}
	{
		var i = (0)
		for ; i < (s.len); i++ {
			if isDecimal(*at(s.s, i)) {
				num_digit += 1
				continue
			}
			if (*at(s.s, i)) == ('.') {
				num_entity -= 1
				continue
			}
			if !isAlphabet(*at(s.s, i)) && (*at(s.s, i)) != ('-') {
				return false
			}
			if (i) != 0 && (*at(s.s, i)) == ('.') && (*at(s.s, (i - (1)))) == ('.') {
				return false
			}
		}
	}
	return num_digit != num_entity
}

func isValidIPv4(s stringSpan) bool {
	{
		var j int
		var i = (0)
		var pos = (0)
		for ; i < (4) && pos < (s.len); i++ {
			var val = (0)
			for j = (0); j < (3) && pos+j < (s.len) && isDecimal(*at(s.s, pos+j)); j++ {
				val = ((10)*(val) + int(*at(s.s, pos+j)) - ('0'))
			}
			if j == (0) || j > (1) && (*at(s.s, pos)) == ('0') || val > (255) {
				return false
			}
			if pos+j == (s.len) && i == (3) {
				return true
			}
			if (*at(s.s, pos+j)) != ('.') {
				return false
			}
			pos += j + (1)
		}
	}
	return false
}

func isValidIPv6(s stringSpan) bool {
	var pos = (0)
	var seenColon = false
	if (s.len) < (2) {
		return false
	}
	if *at(s.s, pos) == ':' {
		pos++
		if *at(s.s, pos) != ':' {
			return false
		}
	}
	if (*at(s.s, ((s.len) - (1)))) == (':') && (*at(s.s, ((s.len) - (2)))) != (':') {
		return false
	}
	{
		var j int
		var i = (0)
		for ; pos < (s.len); i++ {
			if (*at(s.s, pos)) == (':') && !seenColon {
				seenColon = true
				pos++
				if pos == s.len {
					break
				}
				if i == (7) {
					return false
				}
				continue
			}
			for j = (0); ; j++ {
				if j < (4) && pos+j < (s.len) && isHexadecimal(*at(s.s, pos+j)) {
					continue
				}
				break
			}
			if j == (0) {
				return false
			}
			if pos+j == (s.len) && (seenColon || i == (7)) {
				break
			}
			if i == (7) {
				return false
			}
			if (*at(s.s, pos+j)) != (':') {
				if (*at(s.s, pos+j)) != ('.') || i < (6) && !seenColon {
					return false
				}
				return isValidIPv4(stringSpan{at(s.s, pos), (s.len) - pos})
			}
			pos += j + (1)
		}
	}
	return true
}

/* Bound this around 32 bits, so that we don't have to write overflow logic. */
func isValidUint(s stringSpan, support_hex bool, min uint64, max uint64) bool {
	var val = uint64(0)
	if (s.len) > (10) || s.len == 0 {
		return false
	}
	if support_hex && (s.len) > (2) && (*s.s) == ('0') && (*at(s.s, 1)) == ('x') {
		{
			var i = (2)
			for ; i < (s.len); i++ {
				if (*at(s.s, i))-('0') < (10) {
					val = ((16)*(val) + uint64((*at(s.s, i))-('0')))
				} else if (*at(s.s, i))|(32)-('a') < (6) {
					val = ((16)*(val) + uint64((*at(s.s, i))|(32)) - ('a') + (10))
				} else {
					return false
				}
			}
		}
	} else {
		{
			var i = (0)
			for ; i < (s.len); i++ {
				if !isDecimal(*at(s.s, i)) {
					return false
				}
				val = ((10)*(val) + uint64(*at(s.s, i)) - ('0'))
			}
		}
	}
	return val <= max && val >= min
}

func isValidPort(s stringSpan) bool {
	return isValidUint(s, false, (0), (65535))
}

func isValidMTU(s stringSpan) bool {
	return isValidUint(s, false, (576), (65535))
}

func isValidPersistentKeepAlive(s stringSpan) bool {
	if isSame(s, &[]byte("off\x00")[0]) {
		return true
	}
	return isValidUint(s, false, (0), (65535))
}

func isValidFwMark(s stringSpan) bool {
	if isSame(s, &[]byte("off\x00")[0]) {
		return true
	}
	return isValidUint(s, true, (0), (4294967295))
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
	if (s.len) < (512) {
		return true
	}
	return isValidUint(s, false, (0), (4294967295))
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
	if (s.len) > (64) || s.len == 0 {
		return false
	}
	{
		var i = (0)
		for ; i < (s.len); i++ {
			if isAlphabet(*at(s.s, i)) && !isDecimal(*at(s.s, i)) && (*at(s.s, i)) != ('_') && (*at(s.s, i)) != ('=') && (*at(s.s, i)) != ('+') && (*at(s.s, i)) != ('.') && (*at(s.s, i)) != ('-') {
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
	if (*s.s) == ('[') {
		var seenScope = false
		var hostspan = stringSpan{at(s.s, 1), (0)}
		{
			var i = (1)
			for ; i < (s.len); i++ {
				if (*at(s.s, i)) == ('%') {
					if seenScope {
						return false
					}
					seenScope = true
					if !isValidIPv6(hostspan) {
						return false
					}
					hostspan = stringSpan{at(s.s, i+1), (0)}
				} else if (*at(s.s, i)) == (']') {
					if seenScope {
						if !isValidScope(hostspan) {
							return false
						}
					} else if !isValidIPv6(hostspan) {
						return false
					}
					if i == (s.len)-(1) || (*at(s.s, (i + (1)))) != (':') {
						return false
					}
					return isValidPort(stringSpan{at(s.s, i+2), (s.len) - i - (2)})
				} else {
					hostspan.len += (1)
				}
			}
		}
		return false
	}
	{
		var i = (0)
		for ; i < (s.len); i++ {
			if (*at(s.s, i)) == (':') {
				var host = stringSpan{s.s, (i)}
				var port = stringSpan{at(s.s, i+1), (s.len) - i - (1)}
				return isValidPort(port) && (isValidIPv4(host) || isValidHostname(host))
			}
		}
	}
	return false
}

func isValidNetwork(s stringSpan) bool {
	{
		var i = (0)
		for ; i < (s.len); i++ {
			if (*at(s.s, i)) == ('/') {
				var ip = stringSpan{s.s, (i)}
				var cidr = stringSpan{at(s.s, i+1), (s.len) - i - (1)}
				var cidrval = uint16(0)
				if (cidr.len) > (3) || cidr.len == 0 {
					return false
				}
				{
					var j = (0)
					for ; j < (cidr.len); j++ {
						if !isDecimal(*at(cidr.s, j)) {
							return false
						}
						cidrval = ((10)*(cidrval) + uint16(*at(cidr.s, j)) - ('0'))
					}
				}
				if isValidIPv4(ip) {
					return (cidrval) <= (32)
				} else if isValidIPv6(ip) {
					return (cidrval) <= (128)
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
	if (t) > (InterfaceSection) && (t) < (PeerSection) {
		return InterfaceSection
	}
	if (t) > (PeerSection) && (t) < (Invalid) {
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
	addToArray(a, &highlightSpan{t, int((uintptr(unsafe.Pointer(s.s))) - (uintptr(unsafe.Pointer(o)))), (s.len)})
	return true
}

func highlightMultivalueValue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	switch section {
	case (DNS):
		{
			if isValidIPv4(s) || isValidIPv6(s) {
				appendHighlightSpan(ret, parent.s, s, highlightIP)
			} else if isValidHostname(s) {
				appendHighlightSpan(ret, parent.s, s, highlightHost)
			} else {
				appendHighlightSpan(ret, parent.s, s, highlightError)
			}
		}
	case (Address), (AllowedIPs):
		{
			var slash int
			if !isValidNetwork(s) {
				appendHighlightSpan(ret, parent.s, s, highlightError)
				break
			}
			for slash = (0); slash < (s.len); slash++ {
				if (*at(s.s, slash)) == ('/') {
					break
				}
			}
			if slash == (s.len) {
				appendHighlightSpan(ret, parent.s, s, highlightIP)
			} else {
				appendHighlightSpan(ret, parent.s, stringSpan{s.s, (slash)}, highlightIP)
				appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, slash), (1)}, highlightDelimiter)
				appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, slash+1), (s.len) - slash - (1)}, highlightCidr)
			}
		}
	default:
		{
			appendHighlightSpan(ret, parent.s, s, highlightError)
		}
	}
}

func highlightMultivalue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	var currentSpan = stringSpan{s.s, (0)}
	var lenAtLastSpace = (0)
	{
		var i = (0)
		for ; i < (s.len); i++ {
			if (*at(s.s, i)) == (',') {
				currentSpan.len = lenAtLastSpace
				highlightMultivalueValue(ret, stringSpan(parent), stringSpan(currentSpan), section)
				appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, i), (1)}, highlightDelimiter)
				lenAtLastSpace = (0)
				currentSpan = stringSpan{at(s.s, i+1), (0)}
			} else if (*at(s.s, i)) == (' ') || (*at(s.s, i)) == ('\t') {
				if (uintptr(unsafe.Pointer(at(s.s, i)))) == (uintptr(unsafe.Pointer(currentSpan.s))) && currentSpan.len == 0 {
					currentSpan.s = at(currentSpan.s, 1)
				} else {
					currentSpan.len += (1)
				}
			} else {
				currentSpan.len++
				lenAtLastSpace = currentSpan.len
			}
		}
	}
	currentSpan.len = lenAtLastSpace
	if (currentSpan.len) != 0 {
		highlightMultivalueValue(ret, stringSpan(parent), stringSpan(currentSpan), section)
	} else if ((*((*highlightSpan)(func() unsafe.Pointer {
		tempVar := (*ret).spans
		return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)((((*ret).len)-(1)))*unsafe.Sizeof(*tempVar))
	}()))).t) == (highlightDelimiter) {
		(*((*highlightSpan)(func() unsafe.Pointer {
			tempVar := (*ret).spans
			return unsafe.Pointer(uintptr(unsafe.Pointer(tempVar)) + (uintptr)((((*ret).len)-(1)))*unsafe.Sizeof(*tempVar))
		}()))).t = highlightError
	}
}

func highlightValue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	switch section {
	case (PrivateKey):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidKey(s) {
					return (highlightPrivateKey)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (PublicKey):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidKey(s) {
					return (highlightPublicKey)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (PresharedKey):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidKey(s) {
					return (highlightPresharedKey)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (MTU):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidMTU(s) {
					return (highlightMTU)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (SaveConfig):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidSaveConfig(s) {
					return (highlightSaveConfig)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (FwMark):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidFwMark(s) {
					return (highlightFwMark)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (Table):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidTable(s) {
					return (highlightTable)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (PreUp), (PostUp), (PreDown), (PostDown):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidPrePostUpDown(s) {
					return (highlightCmd)
				} else {
					return (highlightError)
				}
			}()))
		}

	case (ListenPort):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidPort(s) {
					return (highlightPort)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (PersistentKeepalive):
		{
			appendHighlightSpan(ret, parent.s, s, highlight(func() int32 {
				if isValidPersistentKeepAlive(s) {
					return (highlightKeepalive)
				} else {
					return (highlightError)
				}
			}()))
		}
	case (Endpoint):
		{
			var colon int
			if !isValidEndpoint(s) {
				appendHighlightSpan(ret, parent.s, s, highlightError)
				break
			}
			for colon = s.len; colon > 0; {
				colon--
				if (*at(s.s, colon)) == (':') {
					break
				}
			}
			appendHighlightSpan(ret, parent.s, stringSpan{s.s, (colon)}, highlightHost)
			appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, colon), (1)}, highlightDelimiter)
			appendHighlightSpan(ret, parent.s, stringSpan{at(s.s, colon+1), (s.len) - colon - (1)}, highlightPort)
		}
	case (Address), (DNS), (AllowedIPs):
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
	var s = stringSpan{config, (cStrlen(config))}
	var currentSpan = stringSpan{s.s, (0)}
	var currentSection field = Invalid
	var currentField field = Invalid
	var state = OnNone
	var lenAtLastSpace = (0)
	var equalsLocation = (0)
	{
		var i = (0)
		for ; i <= (s.len); i++ {
			if i == (s.len) || (*at(s.s, i)) == ('\n') || (state) != (OnComment) && (*at(s.s, i)) == ('#') {
				if (state) == (OnKey) {
					currentSpan.len = lenAtLastSpace
					appendHighlightSpan(&ret, s.s, currentSpan, highlightError)
				} else if (state) == (OnValue) {
					if (currentSpan.len) != 0 {
						appendHighlightSpan(&ret, s.s, stringSpan{at(s.s, equalsLocation), (1)}, highlightDelimiter)
						currentSpan.len = lenAtLastSpace
						highlightValue(&ret, stringSpan(s), stringSpan(currentSpan), currentField)
					} else {
						appendHighlightSpan(&ret, s.s, stringSpan{at(s.s, equalsLocation), (1)}, highlightError)
					}
				} else if (state) == (OnSection) {
					currentSpan.len = lenAtLastSpace
					currentSection = getSectionType(currentSpan)
					appendHighlightSpan(&ret, s.s, currentSpan, highlight(func() highlight {
						if (currentSection) == (Invalid) {
							return (highlightError)
						} else {
							return (highlightSection)
						}
					}()))
				} else if (state) == (OnComment) {
					appendHighlightSpan(&ret, s.s, currentSpan, highlightComment)
				}
				if i == (s.len) {
					break
				}
				lenAtLastSpace = (0)
				currentField = Invalid
				if (*at(s.s, i)) == ('#') {
					currentSpan = stringSpan{at(s.s, i), (1)}
					state = OnComment
				} else {
					currentSpan = stringSpan{at(s.s, i+1), (0)}
					state = OnNone
				}
			} else if (state) == (OnComment) {
				currentSpan.len += (1)
			} else if (*at(s.s, i)) == (' ') || (*at(s.s, i)) == ('\t') {
				if (uintptr(unsafe.Pointer(at(s.s, i)))) == (uintptr(unsafe.Pointer(currentSpan.s))) && currentSpan.len == 0 {
					currentSpan.s = at(currentSpan.s, 1)
				} else {
					currentSpan.len += (1)
				}
			} else if (*at(s.s, i)) == ('=') && (state) == (OnKey) {
				currentSpan.len = lenAtLastSpace
				currentField = getField(currentSpan)
				var section = sectionForField(currentField)
				if (section) == (Invalid) || (currentField) == (Invalid) || (section) != (currentSection) {
					appendHighlightSpan(&ret, s.s, currentSpan, highlightError)
				} else {
					appendHighlightSpan(&ret, s.s, currentSpan, highlightField)
				}
				equalsLocation = i
				currentSpan = stringSpan{at(s.s, i+1), (0)}
				state = OnValue
			} else {
				if (state) == (OnNone) {
					state = parserState(func() int32 {
						if (*at(s.s, i)) == ('[') {
							return (OnSection)
						} else {
							return (OnKey)
						}
					}())
				}
				currentSpan.len++
				lenAtLastSpace = currentSpan.len
			}
		}
	}
	return *(*[]highlightSpan)(unsafe.Pointer(&ret))
}

func highlightConfig(config string) []highlightSpan {
	return highlightConfigInt(&append([]byte(config), 0)[0])
}
