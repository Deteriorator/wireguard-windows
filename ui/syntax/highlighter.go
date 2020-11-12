/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package syntax

import (
	"bytes"
	"unsafe"
)

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

func isDecimal(c byte) bool {
	return c >= '0' && c <= '9'
}

func isHexadecimal(c byte) bool {
	return isDecimal(c) || (c|32) >= 'a' && (c|32) <= 'f'
}

func isAlphabet(c byte) bool {
	return (c|32) >= 'a' && (c|32) <= 'z'
}

type stringSpan struct {
	s   *byte
	len int
}

func (s stringSpan) at(i int) *byte {
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(s.s)) + uintptr(i)))
}

func (s stringSpan) toByteSlice() []byte {
	header := struct {
		ptr unsafe.Pointer
		len int
		cap int
	}{
		unsafe.Pointer(s.s),
		s.len,
		s.len,
	}
	return (*(*[]byte)(unsafe.Pointer(&header)))[:]
}

func (s stringSpan) isSame(c string) bool {
	if s.len != len(c) {
		return false
	}
	return bytes.Compare(s.toByteSlice(), ([]byte)(c)) == 0
}

func (s stringSpan) isCaselessSame(c string) bool {
	if s.len != len(c) {
		return false
	}
	cb := ([]byte)(c)
	for i := 0; i < s.len; i++ {
		a := *s.at(i)
		b := cb[i]
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
	return true
}

func (s stringSpan) isValidKey() bool {
	if s.len != 44 || *s.at(43) != '=' {
		return false
	}
	for i := 0; i < 42; i++ {
		if !isDecimal(*s.at(i)) && !isAlphabet(*s.at(i)) && *s.at(i) != '/' && *s.at(i) != '+' {
			return false
		}
	}
	switch *s.at(42) {
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
	if *s.s == '-' || *s.at(s.len - 1) == '-' {
		return false
	}
	if *s.s == '.' || *s.at(s.len - 1) == '.' {
		return false
	}
	for i := 0; i < s.len; i++ {
		if isDecimal(*s.at(i)) {
			numDigit++
			continue
		}
		if *s.at(i) == '.' {
			numEntity--
			continue
		}
		if !isAlphabet(*s.at(i)) && *s.at(i) != '-' {
			return false
		}
		if i != 0 && *s.at(i) == '.' && *s.at(i - 1) == '.' {
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
		for ; j < 3 && pos+j < s.len && isDecimal(*s.at(pos + j)); j++ {
			val = 10*val + int(*s.at(pos + j)-'0')
		}
		if j == 0 || j > 1 && *s.at(pos) == '0' || val > 255 {
			return false
		}
		if pos+j == s.len && i == 3 {
			return true
		}
		if *s.at(pos + j) != '.' {
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
	if *s.at(0) == ':' {
		if *s.at(1) != ':' {
			return false
		}
		pos = 1
	}
	if *s.at(s.len - 1) == ':' && *s.at(s.len - 2) != ':' {
		return false
	}
	seenColon := false
	for i := 0; pos < s.len; i++ {
		if *s.at(pos) == ':' && !seenColon {
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
			if j < 4 && pos+j < s.len && isHexadecimal(*s.at(pos + j)) {
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
		if *s.at(pos + j) != ':' {
			if *s.at(pos + j) != '.' || i < 6 && !seenColon {
				return false
			}
			return stringSpan{s.at(pos), s.len - pos}.isValidIPv4()
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
	if supportHex && s.len > 2 && *s.s == '0' && *s.at(1) == 'x' {
		for i := 2; i < s.len; i++ {
			if *s.at(i)-'0' < 10 {
				val = 16*val + uint64(*s.at(i)-'0')
			} else if (*s.at(i))|32-'a' < 6 {
				val = 16*val + uint64((*s.at(i)|32)-'a'+10)
			} else {
				return false
			}
		}
	} else {
		for i := 0; i < s.len; i++ {
			if !isDecimal(*s.at(i)) {
				return false
			}
			val = 10*val + uint64(*s.at(i)-'0')
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
	if s.isSame("off") {
		return true
	}
	return s.isValidUint(false, 0, 65535)
}

func (s stringSpan) isValidFwMark() bool {
	if s.isSame("off") {
		return true
	}
	return s.isValidUint(true, 0, 4294967295)
}

// This pretty much invalidates the other checks, but rt_names.c's fread_id_name does no validation aside from this.
func (s stringSpan) isValidTable() bool {
	if s.isSame("auto") {
		return true
	}
	if s.isSame("off") {
		return true
	}
	if s.len < 512 {
		return true
	}
	return s.isValidUint(false, 0, 4294967295)
}

func (s stringSpan) isValidSaveConfig() bool {
	return s.isSame("true") || s.isSame("false")
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
		if isAlphabet(*s.at(i)) && !isDecimal(*s.at(i)) && *s.at(i) != '_' && *s.at(i) != '=' && *s.at(i) != '+' && *s.at(i) != '.' && *s.at(i) != '-' {
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
		hostspan := stringSpan{s.at(1), 0}
		for i := 1; i < s.len; i++ {
			if *s.at(i) == '%' {
				if seenScope {
					return false
				}
				seenScope = true
				if !hostspan.isValidIPv6() {
					return false
				}
				hostspan = stringSpan{s.at(i + 1), 0}
			} else if *s.at(i) == ']' {
				if seenScope {
					if !hostspan.isValidScope() {
						return false
					}
				} else if !hostspan.isValidIPv6() {
					return false
				}
				if i == s.len-1 || *s.at((i + 1)) != ':' {
					return false
				}
				return stringSpan{s.at(i + 2), s.len - i - 2}.isValidPort()
			} else {
				hostspan.len++
			}
		}
		return false
	}
	for i := 0; i < s.len; i++ {
		if *s.at(i) == ':' {
			host := stringSpan{s.s, i}
			port := stringSpan{s.at(i + 1), s.len - i - 1}
			return port.isValidPort() && (host.isValidIPv4() || host.isValidHostname())
		}
	}
	return false
}

func (s stringSpan) isValidNetwork() bool {
	for i := 0; i < s.len; i++ {
		if *s.at(i) == '/' {
			ip := stringSpan{s.s, i}
			cidr := stringSpan{s.at(i + 1), s.len - i - 1}
			cidrval := uint16(0)
			if cidr.len > 3 || cidr.len == 0 {
				return false
			}
			for j := 0; j < cidr.len; j++ {
				if !isDecimal(*cidr.at(j)) {
					return false
				}
				cidrval = 10*cidrval + uint16(*cidr.at(j)-'0')
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
	case s.isCaselessSame("PrivateKey"):
		return PrivateKey
	case s.isCaselessSame("ListenPort"):
		return ListenPort
	case s.isCaselessSame("Address"):
		return Address
	case s.isCaselessSame("DNS"):
		return DNS
	case s.isCaselessSame("MTU"):
		return MTU
	case s.isCaselessSame("PublicKey"):
		return PublicKey
	case s.isCaselessSame("PresharedKey"):
		return PresharedKey
	case s.isCaselessSame("AllowedIPs"):
		return AllowedIPs
	case s.isCaselessSame("Endpoint"):
		return Endpoint
	case s.isCaselessSame("PersistentKeepalive"):
		return PersistentKeepalive
	case s.isCaselessSame("FwMark"):
		return FwMark
	case s.isCaselessSame("Table"):
		return Table
	case s.isCaselessSame("PreUp"):
		return PreUp
	case s.isCaselessSame("PostUp"):
		return PostUp
	case s.isCaselessSame("PreDown"):
		return PreDown
	case s.isCaselessSame("PostDown"):
		return PostDown
	case s.isCaselessSame("SaveConfig"):
		return SaveConfig
	}
	return Invalid
}

func (s stringSpan) sectionType() field {
	switch {
	case s.isCaselessSame("[Peer]"):
		return PeerSection
	case s.isCaselessSame("[Interface]"):
		return InterfaceSection
	}
	return Invalid
}

type highlightSpanArray []highlightSpan

func (hsa *highlightSpanArray) append(o *byte, s stringSpan, t highlight) {
	if s.len == 0 {
		return
	}
	*hsa = append(*hsa, highlightSpan{t, int((uintptr(unsafe.Pointer(s.s))) - (uintptr(unsafe.Pointer(o)))), s.len})
}

func (hsa *highlightSpanArray) highlightMultivalueValue(parent stringSpan, s stringSpan, section field) {
	switch section {
	case DNS:
		if s.isValidIPv4() || s.isValidIPv6() {
			hsa.append(parent.s, s, highlightIP)
		} else if s.isValidHostname() {
			hsa.append(parent.s, s, highlightHost)
		} else {
			hsa.append(parent.s, s, highlightError)
		}
	case Address, AllowedIPs:
		if !s.isValidNetwork() {
			hsa.append(parent.s, s, highlightError)
			break
		}
		slash := 0
		for ; slash < s.len; slash++ {
			if *s.at(slash) == '/' {
				break
			}
		}
		if slash == s.len {
			hsa.append(parent.s, s, highlightIP)
		} else {
			hsa.append(parent.s, stringSpan{s.s, slash}, highlightIP)
			hsa.append(parent.s, stringSpan{s.at(slash), 1}, highlightDelimiter)
			hsa.append(parent.s, stringSpan{s.at(slash + 1), s.len - slash - 1}, highlightCidr)
		}
	default:
		hsa.append(parent.s, s, highlightError)
	}
}

func (hsa *highlightSpanArray) highlightMultivalue(parent stringSpan, s stringSpan, section field) {
	currentSpan := stringSpan{s.s, 0}
	lenAtLastSpace := 0
	for i := 0; i < s.len; i++ {
		if *s.at(i) == ',' {
			currentSpan.len = lenAtLastSpace
			hsa.highlightMultivalueValue(parent, currentSpan, section)
			hsa.append(parent.s, stringSpan{s.at(i), 1}, highlightDelimiter)
			lenAtLastSpace = 0
			currentSpan = stringSpan{s.at(i + 1), 0}
		} else if *s.at(i) == ' ' || *s.at(i) == '\t' {
			if s.at(i) == currentSpan.s && currentSpan.len == 0 {
				currentSpan.s = currentSpan.at(1)
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
		hsa.highlightMultivalueValue(parent, currentSpan, section)
	} else if (*hsa)[len(*hsa)-1].t == highlightDelimiter {
		(*hsa)[len(*hsa)-1].t = highlightError
	}
}

func (hsa *highlightSpanArray) highlightValue(parent stringSpan, s stringSpan, section field) {
	switch section {
	case PrivateKey:
		hsa.append(parent.s, s, validateHighlight(s.isValidKey(), highlightPrivateKey))
	case PublicKey:
		hsa.append(parent.s, s, validateHighlight(s.isValidKey(), highlightPublicKey))
	case PresharedKey:
		hsa.append(parent.s, s, validateHighlight(s.isValidKey(), highlightPresharedKey))
	case MTU:
		hsa.append(parent.s, s, validateHighlight(s.isValidMTU(), highlightMTU))
	case SaveConfig:
		hsa.append(parent.s, s, validateHighlight(s.isValidSaveConfig(), highlightSaveConfig))
	case FwMark:
		hsa.append(parent.s, s, validateHighlight(s.isValidFwMark(), highlightFwMark))
	case Table:
		hsa.append(parent.s, s, validateHighlight(s.isValidTable(), highlightTable))
	case PreUp, PostUp, PreDown, PostDown:
		hsa.append(parent.s, s, validateHighlight(s.isValidPrePostUpDown(), highlightCmd))
	case ListenPort:
		hsa.append(parent.s, s, validateHighlight(s.isValidPort(), highlightPort))
	case PersistentKeepalive:
		hsa.append(parent.s, s, validateHighlight(s.isValidPersistentKeepAlive(), highlightKeepalive))
	case Endpoint:
		if !s.isValidEndpoint() {
			hsa.append(parent.s, s, highlightError)
			break
		}
		colon := s.len
		for colon > 0 {
			colon--
			if *s.at(colon) == ':' {
				break
			}
		}
		hsa.append(parent.s, stringSpan{s.s, colon}, highlightHost)
		hsa.append(parent.s, stringSpan{s.at(colon), 1}, highlightDelimiter)
		hsa.append(parent.s, stringSpan{s.at(colon + 1), s.len - colon - 1}, highlightPort)
	case Address, DNS, AllowedIPs:
		hsa.highlightMultivalue(parent, s, section)
	default:
		hsa.append(parent.s, s, highlightError)
	}
}

func highlightConfig(config string) []highlightSpan {
	var ret highlightSpanArray
	s := stringSpan{&append([]byte(config), 0)[0], len(config)}
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
		if i == s.len || *s.at(i) == '\n' || state != onComment && *s.at(i) == '#' {
			if state == onKey {
				currentSpan.len = lenAtLastSpace
				ret.append(s.s, currentSpan, highlightError)
			} else if state == onValue {
				if currentSpan.len != 0 {
					ret.append(s.s, stringSpan{s.at(equalsLocation), 1}, highlightDelimiter)
					currentSpan.len = lenAtLastSpace
					ret.highlightValue(s, currentSpan, currentField)
				} else {
					ret.append(s.s, stringSpan{s.at(equalsLocation), 1}, highlightError)
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
			if *s.at(i) == '#' {
				currentSpan = stringSpan{s.at(i), 1}
				state = onComment
			} else {
				currentSpan = stringSpan{s.at(i + 1), 0}
				state = onNone
			}
		} else if state == onComment {
			currentSpan.len++
		} else if *s.at(i) == ' ' || *s.at(i) == '\t' {
			if s.at(i) == currentSpan.s && currentSpan.len == 0 {
				currentSpan.s = currentSpan.at(1)
			} else {
				currentSpan.len++
			}
		} else if *s.at(i) == '=' && state == onKey {
			currentSpan.len = lenAtLastSpace
			currentField = currentSpan.field()
			section := sectionForField(currentField)
			if section == Invalid || currentField == Invalid || section != currentSection {
				ret.append(s.s, currentSpan, highlightError)
			} else {
				ret.append(s.s, currentSpan, highlightField)
			}
			equalsLocation = i
			currentSpan = stringSpan{s.at(i + 1), 0}
			state = onValue
		} else {
			if state == onNone {
				if *s.at(i) == '[' {
					state = onSection
				} else {
					state = onKey
				}
			}
			currentSpan.len++
			lenAtLastSpace = currentSpan.len
		}
	}
	return ([]highlightSpan)(ret)
}
