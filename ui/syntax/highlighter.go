/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
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
	highlightSection highlight = iota
	highlightField
	highlightPrivateKey
	highlightPublicKey
	highlightPresharedKey
	highlightIP
	highlightCidr
	highlightHost
	highlightPort
	highlightMTU
	highlightKeepalive
	highlightComment
	highlightDelimiter
	highlightTable
	highlightFwMark
	highlightSaveConfig
	highlightCmd
	highlightError
)

func validateHighlight(isValid bool, t highlight) highlight {
	if isValid {
		return t
	}
	return highlightError
}

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
	return c >= '0' && c <= '9'
}

func isHexadecimal(c byte) bool {
	return isDecimal(c) || (c|32) >= 'a' && (c|32) <= 'f'
}

func isAlphabet(c byte) bool {
	return (c|32) >= 'a' && (c|32) <= 'z'
}

func (s stringSpan) isSame(c *byte) bool {
	if cStrlen(c) != s.len {
		return false
	}
	return cMemcmp(unsafe.Pointer(s.s), unsafe.Pointer(c), s.len) == 0
}

func (s stringSpan) isCaselessSame(c *byte) bool {
	if cStrlen(c) != s.len {
		return false
	}
	{
		for i := 0; i < s.len; i++ {
			a := *at(c, i)
			b := *at(s.s, i)
			if a-'a' < 26 {
				a &= 95
			}
			if b-'a' < 26 {
				b &= 95
			}
			if a != b {
				return false
			}
		}
	}
	return true
}

func (s stringSpan) isValidKey() bool {
	if s.len != 44 || *at(s.s, 43) != '=' {
		return false
	}
	for i := 0; i < 42; i++ {
		if !isDecimal(*at(s.s, i)) && !isAlphabet(*at(s.s, i)) && *at(s.s, i) != '/' && *at(s.s, i) != '+' {
			return false
		}
	}
	switch *at(s.s, 42) {
	case 'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '4', '8', '0':
		return true
	}
	return false
}

func (s stringSpan) isValidHostname() bool {
	numDigit := 0
	numEntity := s.len
	if s.len > 63 || s.len == 0 {
		return false
	}
	if *s.s == '-' || *at(s.s, s.len-1) == '-' {
		return false
	}
	if *s.s == '.' || *at(s.s, s.len-1) == '.' {
		return false
	}
	for i := 0; i < s.len; i++ {
		if isDecimal(*at(s.s, i)) {
			numDigit++
			continue
		}
		if *at(s.s, i) == '.' {
			numEntity--
			continue
		}
		if !isAlphabet(*at(s.s, i)) && *at(s.s, i) != '-' {
			return false
		}
		if i != 0 && *at(s.s, i) == '.' && *at(s.s, i-1) == '.' {
			return false
		}
	}
	return numDigit != numEntity
}

func (s stringSpan) isValidIPv4() bool {
	pos := 0
	for i := 0; i < 4 && pos < s.len; i++ {
		val := 0
		j := 0
		for ; j < 3 && pos+j < s.len && isDecimal(*at(s.s, pos+j)); j++ {
			val = 10*val + int(*at(s.s, pos+j)-'0')
		}
		if j == 0 || j > 1 && *at(s.s, pos) == '0' || val > 255 {
			return false
		}
		if pos+j == s.len && i == 3 {
			return true
		}
		if *at(s.s, pos+j) != '.' {
			return false
		}
		pos += j + 1
	}
	return false
}

func (s stringSpan) isValidIPv6() bool {
	if s.len < 2 {
		return false
	}
	pos := 0
	if *at(s.s, 0) == ':' {
		if *at(s.s, 1) != ':' {
			return false
		}
		pos = 1
	}
	if *at(s.s, s.len-1) == ':' && *at(s.s, s.len-2) != ':' {
		return false
	}
	seenColon := false
	for i := 0; pos < s.len; i++ {
		if *at(s.s, pos) == ':' && !seenColon {
			seenColon = true
			pos++
			if pos == s.len {
				break
			}
			if i == 7 {
				return false
			}
			continue
		}
		j := 0
		for ; ; j++ {
			if j < 4 && pos+j < s.len && isHexadecimal(*at(s.s, pos+j)) {
				continue
			}
			break
		}
		if j == 0 {
			return false
		}
		if pos+j == s.len && (seenColon || i == 7) {
			break
		}
		if i == 7 {
			return false
		}
		if *at(s.s, pos+j) != ':' {
			if *at(s.s, pos+j) != '.' || i < 6 && !seenColon {
				return false
			}
			return stringSpan{at(s.s, pos), s.len - pos}.isValidIPv4()
		}
		pos += j + 1
	}
	return true
}

// Bound this around 32 bits, so that we don't have to write overflow logic.
func (s stringSpan) isValidUint(supportHex bool, min uint64, max uint64) bool {
	if s.len > 10 || s.len == 0 {
		return false
	}
	val := uint64(0)
	if supportHex && s.len > 2 && *s.s == '0' && *at(s.s, 1) == 'x' {
		for i := 2; i < s.len; i++ {
			if *at(s.s, i)-'0' < 10 {
				val = 16*val + uint64(*at(s.s, i)-'0')
			} else if (*at(s.s, i))|32-'a' < 6 {
				val = 16*val + uint64((*at(s.s, i)|32)-'a'+10)
			} else {
				return false
			}
		}
	} else {
		for i := 0; i < s.len; i++ {
			if !isDecimal(*at(s.s, i)) {
				return false
			}
			val = 10*val + uint64(*at(s.s, i)-'0')
		}
	}
	return val <= max && val >= min
}

func (s stringSpan) isValidPort() bool {
	return s.isValidUint(false, 0, 65535)
}

func (s stringSpan) isValidMTU() bool {
	return s.isValidUint(false, 576, 65535)
}

func (s stringSpan) isValidPersistentKeepAlive() bool {
	if s.isSame(&[]byte("off\x00")[0]) {
		return true
	}
	return s.isValidUint(false, 0, 65535)
}

func (s stringSpan) isValidFwMark() bool {
	if s.isSame(&[]byte("off\x00")[0]) {
		return true
	}
	return s.isValidUint(true, 0, 4294967295)
}

// This pretty much invalidates the other checks, but rt_names.c's fread_id_name does no validation aside from this.
func (s stringSpan) isValidTable() bool {
	if s.isSame(&[]byte("auto\x00")[0]) {
		return true
	}
	if s.isSame(&[]byte("off\x00")[0]) {
		return true
	}
	if s.len < 512 {
		return true
	}
	return s.isValidUint(false, 0, 4294967295)
}

func (s stringSpan) isValidSaveConfig() bool {
	return s.isSame(&[]byte("true\x00")[0]) || s.isSame(&[]byte("false\x00")[0])
}

// It's probably not worthwhile to try to validate a bash expression. So instead we just demand non-zero length.
func (s stringSpan) isValidPrePostUpDown() bool {
	return s.len != 0
}

func (s stringSpan) isValidScope() bool {
	if s.len > 64 || s.len == 0 {
		return false
	}
	for i := 0; i < s.len; i++ {
		if isAlphabet(*at(s.s, i)) && !isDecimal(*at(s.s, i)) && *at(s.s, i) != '_' && *at(s.s, i) != '=' && *at(s.s, i) != '+' && *at(s.s, i) != '.' && *at(s.s, i) != '-' {
			return false
		}
	}
	return true
}

func (s stringSpan) isValidEndpoint() bool {
	if s.len == 0 {
		return false
	}
	if *s.s == '[' {
		seenScope := false
		hostspan := stringSpan{at(s.s, 1), 0}
		for i := 1; i < s.len; i++ {
			if *at(s.s, i) == '%' {
				if seenScope {
					return false
				}
				seenScope = true
				if !hostspan.isValidIPv6() {
					return false
				}
				hostspan = stringSpan{at(s.s, i+1), 0}
			} else if *at(s.s, i) == ']' {
				if seenScope {
					if !hostspan.isValidScope() {
						return false
					}
				} else if !hostspan.isValidIPv6() {
					return false
				}
				if i == s.len-1 || *at(s.s, (i + 1)) != ':' {
					return false
				}
				return stringSpan{at(s.s, i+2), s.len - i - 2}.isValidPort()
			} else {
				hostspan.len++
			}
		}
		return false
	}
	for i := 0; i < s.len; i++ {
		if *at(s.s, i) == ':' {
			host := stringSpan{s.s, i}
			port := stringSpan{at(s.s, i+1), s.len - i - 1}
			return port.isValidPort() && (host.isValidIPv4() || host.isValidHostname())
		}
	}
	return false
}

func (s stringSpan) isValidNetwork() bool {
	for i := 0; i < s.len; i++ {
		if *at(s.s, i) == '/' {
			ip := stringSpan{s.s, i}
			cidr := stringSpan{at(s.s, i+1), s.len - i - 1}
			cidrval := uint16(0)
			if cidr.len > 3 || cidr.len == 0 {
				return false
			}
			for j := 0; j < cidr.len; j++ {
				if !isDecimal(*at(cidr.s, j)) {
					return false
				}
				cidrval = 10*cidrval + uint16(*at(cidr.s, j)-'0')
			}
			if ip.isValidIPv4() {
				return cidrval <= 32
			} else if ip.isValidIPv6() {
				return cidrval <= 128
			}
			return false
		}
	}
	return s.isValidIPv4() || s.isValidIPv6()
}

type field int32

const (
	InterfaceSection field = iota
	PrivateKey
	ListenPort
	Address
	DNS
	MTU
	FwMark
	Table
	PreUp
	PostUp
	PreDown
	PostDown
	SaveConfig
	PeerSection
	PublicKey
	PresharedKey
	AllowedIPs
	Endpoint
	PersistentKeepalive
	Invalid
)

func sectionForField(t field) field {
	if t > InterfaceSection && t < PeerSection {
		return InterfaceSection
	}
	if t > PeerSection && t < Invalid {
		return PeerSection
	}
	return Invalid
}

func (s stringSpan) field() field {
	switch {
	case s.isCaselessSame(&[]byte("PrivateKey\x00")[0]):
		return PrivateKey
	case s.isCaselessSame(&[]byte("ListenPort\x00")[0]):
		return ListenPort
	case s.isCaselessSame(&[]byte("Address\x00")[0]):
		return Address
	case s.isCaselessSame(&[]byte("DNS\x00")[0]):
		return DNS
	case s.isCaselessSame(&[]byte("MTU\x00")[0]):
		return MTU
	case s.isCaselessSame(&[]byte("PublicKey\x00")[0]):
		return PublicKey
	case s.isCaselessSame(&[]byte("PresharedKey\x00")[0]):
		return PresharedKey
	case s.isCaselessSame(&[]byte("AllowedIPs\x00")[0]):
		return AllowedIPs
	case s.isCaselessSame(&[]byte("Endpoint\x00")[0]):
		return Endpoint
	case s.isCaselessSame(&[]byte("PersistentKeepalive\x00")[0]):
		return PersistentKeepalive
	case s.isCaselessSame(&[]byte("FwMark\x00")[0]):
		return FwMark
	case s.isCaselessSame(&[]byte("Table\x00")[0]):
		return Table
	case s.isCaselessSame(&[]byte("PreUp\x00")[0]):
		return PreUp
	case s.isCaselessSame(&[]byte("PostUp\x00")[0]):
		return PostUp
	case s.isCaselessSame(&[]byte("PreDown\x00")[0]):
		return PreDown
	case s.isCaselessSame(&[]byte("PostDown\x00")[0]):
		return PostDown
	case s.isCaselessSame(&[]byte("SaveConfig\x00")[0]):
		return SaveConfig
	}
	return Invalid
}

func (s stringSpan) sectionType() field {
	switch {
	case s.isCaselessSame(&[]byte("[Peer]\x00")[0]):
		return PeerSection
	case s.isCaselessSame(&[]byte("[Interface]\x00")[0]):
		return InterfaceSection
	}
	return Invalid
}

type highlightSpanArray []highlightSpan

func (a *highlightSpanArray) append(o *byte, s stringSpan, t highlight) {
	if s.len == 0 {
		return
	}
	*a = append(*a, highlightSpan{t, int((uintptr(unsafe.Pointer(s.s))) - (uintptr(unsafe.Pointer(o)))), s.len})
}

func highlightMultivalueValue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	switch section {
	case DNS:
		if s.isValidIPv4() || s.isValidIPv6() {
			ret.append(parent.s, s, highlightIP)
		} else if s.isValidHostname() {
			ret.append(parent.s, s, highlightHost)
		} else {
			ret.append(parent.s, s, highlightError)
		}
	case Address, AllowedIPs:
		if !s.isValidNetwork() {
			ret.append(parent.s, s, highlightError)
			break
		}
		slash := 0
		for ; slash < s.len; slash++ {
			if *at(s.s, slash) == '/' {
				break
			}
		}
		if slash == s.len {
			ret.append(parent.s, s, highlightIP)
		} else {
			ret.append(parent.s, stringSpan{s.s, slash}, highlightIP)
			ret.append(parent.s, stringSpan{at(s.s, slash), 1}, highlightDelimiter)
			ret.append(parent.s, stringSpan{at(s.s, slash+1), s.len - slash - 1}, highlightCidr)
		}
	default:
		ret.append(parent.s, s, highlightError)
	}
}

func highlightMultivalue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	currentSpan := stringSpan{s.s, 0}
	lenAtLastSpace := 0
	for i := 0; i < s.len; i++ {
		if *at(s.s, i) == ',' {
			currentSpan.len = lenAtLastSpace
			highlightMultivalueValue(ret, parent, currentSpan, section)
			ret.append(parent.s, stringSpan{at(s.s, i), 1}, highlightDelimiter)
			lenAtLastSpace = 0
			currentSpan = stringSpan{at(s.s, i+1), 0}
		} else if *at(s.s, i) == ' ' || *at(s.s, i) == '\t' {
			if at(s.s, i) == currentSpan.s && currentSpan.len == 0 {
				currentSpan.s = at(currentSpan.s, 1)
			} else {
				currentSpan.len++
			}
		} else {
			currentSpan.len++
			lenAtLastSpace = currentSpan.len
		}
	}
	currentSpan.len = lenAtLastSpace
	if currentSpan.len != 0 {
		highlightMultivalueValue(ret, parent, currentSpan, section)
	} else if (*ret)[len(*ret)-1].t == highlightDelimiter {
		(*ret)[len(*ret)-1].t = highlightError
	}
}

func highlightValue(ret *highlightSpanArray, parent stringSpan, s stringSpan, section field) {
	switch section {
	case PrivateKey:
		ret.append(parent.s, s, validateHighlight(s.isValidKey(), highlightPrivateKey))
	case PublicKey:
		ret.append(parent.s, s, validateHighlight(s.isValidKey(), highlightPublicKey))
	case PresharedKey:
		ret.append(parent.s, s, validateHighlight(s.isValidKey(), highlightPresharedKey))
	case MTU:
		ret.append(parent.s, s, validateHighlight(s.isValidMTU(), highlightMTU))
	case SaveConfig:
		ret.append(parent.s, s, validateHighlight(s.isValidSaveConfig(), highlightSaveConfig))
	case FwMark:
		ret.append(parent.s, s, validateHighlight(s.isValidFwMark(), highlightFwMark))
	case Table:
		ret.append(parent.s, s, validateHighlight(s.isValidTable(), highlightTable))
	case PreUp, PostUp, PreDown, PostDown:
		ret.append(parent.s, s, validateHighlight(s.isValidPrePostUpDown(), highlightCmd))
	case ListenPort:
		ret.append(parent.s, s, validateHighlight(s.isValidPort(), highlightPort))
	case PersistentKeepalive:
		ret.append(parent.s, s, validateHighlight(s.isValidPersistentKeepAlive(), highlightKeepalive))
	case Endpoint:
		if !s.isValidEndpoint() {
			ret.append(parent.s, s, highlightError)
			break
		}
		colon := s.len
		for colon > 0 {
			colon--
			if *at(s.s, colon) == ':' {
				break
			}
		}
		ret.append(parent.s, stringSpan{s.s, colon}, highlightHost)
		ret.append(parent.s, stringSpan{at(s.s, colon), 1}, highlightDelimiter)
		ret.append(parent.s, stringSpan{at(s.s, colon+1), s.len - colon - 1}, highlightPort)
	case Address, DNS, AllowedIPs:
		highlightMultivalue(ret, parent, s, section)
	default:
		ret.append(parent.s, s, highlightError)
	}
}

func highlightConfigInt(config *byte) []highlightSpan {
	var ret highlightSpanArray
	s := stringSpan{config, cStrlen(config)}
	currentSpan := stringSpan{s.s, 0}
	currentSection := Invalid
	currentField := Invalid
	const (
		onNone = iota
		onKey
		onValue
		onComment
		onSection
	)
	state := onNone
	lenAtLastSpace := 0
	equalsLocation := 0
	for i := 0; i <= s.len; i++ {
		if i == s.len || *at(s.s, i) == '\n' || state != onComment && *at(s.s, i) == '#' {
			if state == onKey {
				currentSpan.len = lenAtLastSpace
				ret.append(s.s, currentSpan, highlightError)
			} else if state == onValue {
				if currentSpan.len != 0 {
					ret.append(s.s, stringSpan{at(s.s, equalsLocation), 1}, highlightDelimiter)
					currentSpan.len = lenAtLastSpace
					highlightValue(&ret, s, currentSpan, currentField)
				} else {
					ret.append(s.s, stringSpan{at(s.s, equalsLocation), 1}, highlightError)
				}
			} else if state == onSection {
				currentSpan.len = lenAtLastSpace
				currentSection = currentSpan.sectionType()
				ret.append(s.s, currentSpan, validateHighlight(currentSection != Invalid, highlightSection))
			} else if state == onComment {
				ret.append(s.s, currentSpan, highlightComment)
			}
			if i == s.len {
				break
			}
			lenAtLastSpace = 0
			currentField = Invalid
			if *at(s.s, i) == '#' {
				currentSpan = stringSpan{at(s.s, i), 1}
				state = onComment
			} else {
				currentSpan = stringSpan{at(s.s, i+1), 0}
				state = onNone
			}
		} else if state == onComment {
			currentSpan.len++
		} else if *at(s.s, i) == ' ' || *at(s.s, i) == '\t' {
			if at(s.s, i) == currentSpan.s && currentSpan.len == 0 {
				currentSpan.s = at(currentSpan.s, 1)
			} else {
				currentSpan.len++
			}
		} else if *at(s.s, i) == '=' && state == onKey {
			currentSpan.len = lenAtLastSpace
			currentField = currentSpan.field()
			section := sectionForField(currentField)
			if section == Invalid || currentField == Invalid || section != currentSection {
				ret.append(s.s, currentSpan, highlightError)
			} else {
				ret.append(s.s, currentSpan, highlightField)
			}
			equalsLocation = i
			currentSpan = stringSpan{at(s.s, i+1), 0}
			state = onValue
		} else {
			if state == onNone {
				if *at(s.s, i) == '[' {
					state = onSection
				} else {
					state = onKey
				}
			}
			currentSpan.len++
			lenAtLastSpace = currentSpan.len
		}
	}
	return *(*[]highlightSpan)(unsafe.Pointer(&ret))
}

func highlightConfig(config string) []highlightSpan {
	return highlightConfigInt(&append([]byte(config), 0)[0])
}
