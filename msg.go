package gfd

import (
	"bufio"
	crcrand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
)

type Msg struct {
	MsgId   string
	Head    []byte
	Payload []byte
}

type MsgVal struct {
	ValType string
	ValText string
	ValByte []byte
	ValList []MsgVal
	ValMap  map[string]MsgVal
	ValErr  error
}

type MsgMap map[string]MsgVal

func (m *Msg) check() (e error) {
	if len(m.MsgId) != 64 {
		return errors.New("msgid error")
	}
	if len(m.Head) < 48 {
		return errors.New("wrong msg block length")
	}
	if hex.EncodeToString(m.Head[:32]) != m.MsgId {
		return errors.New("wrong head msgid")
	}
	headlen := binary.BigEndian.Uint64(m.Head[32:40])
	payloadlen := binary.BigEndian.Uint64(m.Head[40:48])
	if int64(headlen) != int64(len(m.Head)) {
		return errors.New("wrong head length")
	}
	if int64(payloadlen) != int64(len(m.Payload)) {
		return errors.New("wrong payload length")
	}
	allheaditemlen := headlen - 48
	if (headlen-48)%32 != 0 {
		return errors.New("wrong head length")
	}
	var keystart uint64
	var keyend uint64
	var valstart uint64
	var valend uint64
	var i uint64 = 0
	for i = 0; i < (allheaditemlen)/32; i++ {
		fp := 48 + i*32
		keystart = binary.BigEndian.Uint64(m.Head[fp : fp+8])
		keyend = binary.BigEndian.Uint64(m.Head[fp+8 : fp+16])
		valstart = binary.BigEndian.Uint64(m.Head[fp+16 : fp+24])
		valend = binary.BigEndian.Uint64(m.Head[fp+24 : fp+32])
		if keyend < keystart {
			return errors.New("msg wrong head key index")
		}
		if valend < valstart {
			return errors.New("msg wrong head val index")
		}
	}
	return e
}

func (m *MsgVal) check(parentchain []MsgVal, mm map[string]MsgVal) (e error) {
	if m.ValType == "map" {
		if reflect.DeepEqual(m.ValMap, mm) {
			return errors.New("wrong data structure self-referenced")
		}
	}
	switch m.ValType {
	case "list", "map":
		{
			for _, item := range parentchain {
				if reflect.DeepEqual(item, m) {
					return errors.New("wrong data structure self-referenced")
				}
			}
			parentchain = append(parentchain, *m)
			if len(m.ValList) > 0 {
				for _, v := range m.ValList {
					for _, item := range parentchain {
						if reflect.DeepEqual(item, v) {
							return errors.New("wrong data structure self-referenced")
						}
					}
					e = v.check(parentchain, mm)
					if e != nil {
						return e
					}
				}
			}
			if len(m.ValMap) > 0 {
				for k, v := range m.ValMap {
					if k == "MsgId" {
						continue
					}
					for _, item := range parentchain {
						if reflect.DeepEqual(item, v) {
							return errors.New("wrong data structure self-referenced")
						}
					}
					e = v.check(parentchain, mm)
					if e != nil {
						return e
					}
				}
			}
		}
	}
	return e
}

func scopeRandomSlowly(scope string, n int) string {
	var table09 = []rune("0123456789")
	var tableaz = []rune("abcdefghijklmnopqrstuvwxyz")
	var tableAZ = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var tablehex = []rune("0123456789abcdef")
	var scopetable []rune
	runes := []rune{}
	switch scope {
	case "0-9":
		{
			scopetable = table09
		}
	case "a-z":
		{
			scopetable = tableaz
		}
	case "A-Z":
		{
			scopetable = tableAZ
		}
	case "0-9-a-z":
		{
			scopetable = append([]rune{}, table09...)
			scopetable = append(scopetable, tableaz...)
		}
	case "hex":
		{
			scopetable = tablehex
		}
	case "0-9-A-Z":
		{
			scopetable = append([]rune{}, table09...)
			scopetable = append(scopetable, tableAZ...)
		}
	case "0-9-a-z-A-Z":
		{
			scopetable = append([]rune{}, table09...)
			scopetable = append(scopetable, tableaz...)
			scopetable = append(scopetable, tableAZ...)
		}
	default:
		scopetable = table09
	}
	for i := 0; i < n; i++ {
		j, _ := crcrand.Int(crcrand.Reader, big.NewInt(int64(len(scopetable))))
		runes = append(runes, scopetable[j.Int64()])
	}
	return string(runes)
}

func parseMsgVal(payload []byte, valstart, valend uint64) (r MsgVal) {
	r = MsgVal{}
	if valstart > valend {
		r.ValErr = errors.New("wrong val byte")
		return r
	}
	valbytes := payload[valstart:valend]
	valbyteslen := len(valbytes)
	if valbyteslen < 1 {
		r.ValErr = errors.New("notfound")
		return r
	}

	switch byte(valbytes[0]) {
	case byte(1):
		{
			r.ValType = "text"
			r.ValText = string(valbytes[1:])
		}
	case byte(2):
		{
			r.ValType = "byte"
			r.ValByte = valbytes[1:]
		}
	case byte(3):
		{
			r.ValType = "list"
			r.ValList = []MsgVal{}
			if valbyteslen < 9 {
				r.ValErr = errors.New("wrong val byte")
				return r
			}
			listitemnum := binary.BigEndian.Uint64(valbytes[1:9])

			var i uint64
			var fp uint64
			for i = 0; i < listitemnum; i++ {
				fp = 16*i + 9
				valstart := binary.BigEndian.Uint64(valbytes[fp : fp+8])
				valend := binary.BigEndian.Uint64(valbytes[fp+8 : fp+16])
				val := parseMsgVal(payload, valstart, valend)
				r.ValList = append(r.ValList, val)
			}
		}
	case byte(4):
		{
			r.ValType = "map"
			r.ValMap = make(map[string]MsgVal)
			if valbyteslen < 9 {
				r.ValErr = errors.New("wrong val byte")
				return r
			}
			mapitemnum := binary.BigEndian.Uint64(valbytes[1:9])
			var i uint64
			var fp uint64
			for i = 0; i < mapitemnum; i++ {
				fp = 32*i + 9
				keystart := binary.BigEndian.Uint64(valbytes[fp : fp+8])
				keyend := binary.BigEndian.Uint64(valbytes[fp+8 : fp+16])
				valstart := binary.BigEndian.Uint64(valbytes[fp+16 : fp+24])
				valend := binary.BigEndian.Uint64(valbytes[fp+24 : fp+32])
				key := string(payload[keystart:keyend])
				val := parseMsgVal(payload, valstart, valend)
				r.ValMap[key] = val
			}
		}
	}
	return r
}

func formatMsgVal(mv MsgVal, cursor uint64) (r []byte, e error) {
	if mv.ValErr != nil {
		return r, mv.ValErr
	}
	switch mv.ValType {
	case "text":
		{
			r = append([]byte{}, byte(1))
			r = append(r, []byte(mv.ValText)...)
		}
	case "byte":
		{
			r = append([]byte{}, byte(2))
			r = append(r, mv.ValByte...)
		}
	case "list":
		{
			r = append([]byte{}, byte(3))
			listlen := len(mv.ValList)
			listlenbyte := make([]byte, 8)
			binary.BigEndian.PutUint64(listlenbyte, uint64(listlen))
			r = append(r, listlenbyte...)
			indbytes := make([]byte, 16*listlen)
			r = append(r, indbytes...)
			cursor = cursor + uint64(16*listlen) + 9
			for i := 0; i < listlen; i++ {
				itemstart := cursor
				item, err := formatMsgVal(mv.ValList[i], itemstart)
				if err != nil {
					return r, errors.New("format msgval err")
				}
				itemend := itemstart + uint64(len(item))
				cursor = itemend
				fp := 16*i + 9
				binary.BigEndian.PutUint64(r[fp:fp+8], itemstart)
				binary.BigEndian.PutUint64(r[fp+8:fp+16], itemend)
				r = append(r, item...)
			}
		}
	case "map":
		{
			r = append([]byte{}, byte(4))
			maplen := len(mv.ValMap)
			if _, ok := mv.ValMap["MsgId"]; ok {
				maplen = maplen - 1
			}
			maplenbyte := make([]byte, 8)
			binary.BigEndian.PutUint64(maplenbyte, uint64(maplen))
			r = append(r, maplenbyte...)
			indbytes := make([]byte, 32*maplen)
			r = append(r, indbytes...)
			cursor = cursor + uint64(32*maplen) + 9
			var i int = 0
			for k, v := range mv.ValMap {
				if k == "MsgId" {
					continue
				}
				keystart := cursor
				keybytes := []byte(k)
				keyend := keystart + uint64(len(keybytes))
				valstart := keyend
				valbytes, err := formatMsgVal(v, valstart)
				if err != nil {
					return r, errors.New("format msgval err")
				}
				valend := valstart + uint64(len(valbytes))
				cursor = valend
				fp := 32*i + 9
				binary.BigEndian.PutUint64(r[fp:fp+8], keystart)
				binary.BigEndian.PutUint64(r[fp+8:fp+16], keyend)
				binary.BigEndian.PutUint64(r[fp+16:fp+24], valstart)
				binary.BigEndian.PutUint64(r[fp+24:fp+32], valend)
				r = append(r, keybytes...)
				r = append(r, valbytes...)
				i = i + 1
			}
		}
	default:
		return r, errors.New("unknown msgval type")
	}
	return r, e
}

func genMsgVal(val interface{}) (r []byte, e error) {
	if valtext, ok := val.(string); ok {
		r = append([]byte{}, byte(1))
		r = append(r, []byte(valtext)...)
	} else if valbyte, ok := val.([]byte); ok {
		r = append([]byte{}, byte(2))
		r = append(r, valbyte...)
	} else {
		return r, errors.New("val type is not string/[]byte")
	}
	return r, e
}

func (m *Msg) Set(key string, val interface{}) (err error) {
	err = m.check()
	if err != nil {
		return err
	}
	findkey := false
	headlen := binary.BigEndian.Uint64(m.Head[32:40])
	payloadlen := binary.BigEndian.Uint64(m.Head[40:48])
	newmsgval, err := genMsgVal(val)
	if err != nil {
		return err
	}
	var keystart uint64
	var keyend uint64
	var valstart uint64
	var valend uint64
	var fp uint64
	allheaditemlen := headlen - 48
	var i uint64 = 0
	for i = 0; i < (allheaditemlen)/32; i++ {
		fp = 48 + i*32
		keystart = binary.BigEndian.Uint64(m.Head[fp : fp+8])
		keyend = binary.BigEndian.Uint64(m.Head[fp+8 : fp+16])
		if string(m.Payload[keystart:keyend]) == key {
			findkey = true
			valstart = binary.BigEndian.Uint64(m.Head[fp+16 : fp+24])
			valend = binary.BigEndian.Uint64(m.Head[fp+24 : fp+32])
			break
		}
	}

	if findkey {
		newmsgvallen := len(newmsgval)
		centerlen := int64(newmsgvallen) - int64(valend-valstart)
		binary.BigEndian.PutUint64(m.Head[fp+24:fp+32], valstart+uint64(len(newmsgval)))
		if centerlen <= 0 {
			copy(m.Payload[valstart:valend], newmsgval)
		} else {
			left := m.Payload[:valstart]
			right := m.Payload[valend:]
			tmp := append([]byte{}, left...)
			tmp = append(tmp, newmsgval...)
			tmp = append(tmp, right...)
			m.Payload = tmp
			binary.BigEndian.PutUint64(m.Head[40:48], payloadlen+uint64(centerlen))
		}
	} else {
		headlen = headlen + 32
		binary.BigEndian.PutUint64(m.Head[32:40], headlen)

		newitem := []byte(key)
		keylen := len(newitem)

		newitem = append(newitem, newmsgval...)
		m.Payload = append(m.Payload, newitem...)
		newitemlen := len(newitem)
		newpayloadlen := payloadlen + uint64(newitemlen)
		binary.BigEndian.PutUint64(m.Head[40:48], newpayloadlen)
		keystart := make([]byte, 8)
		binary.BigEndian.PutUint64(keystart, payloadlen)
		keyend := make([]byte, 8)
		binary.BigEndian.PutUint64(keyend, payloadlen+uint64(keylen))
		valend := make([]byte, 8)
		binary.BigEndian.PutUint64(valend, newpayloadlen)
		newheaditem := append([]byte{}, keystart...)
		newheaditem = append(newheaditem, keyend...)
		newheaditem = append(newheaditem, keyend...)
		newheaditem = append(newheaditem, valend...)
		m.Head = append(m.Head, newheaditem...)
	}
	return err
}

func (m *Msg) Remove(key string) (err error) {
	err = m.check()
	if err != nil {
		return err
	}
	findkey := false
	headlen := binary.BigEndian.Uint64(m.Head[32:40])
	allheaditemlen := headlen - 48
	var keystart uint64
	var keyend uint64
	var valend uint64
	var fp uint64
	var i uint64 = 0
	for i = 0; i < (allheaditemlen)/32; i++ {
		fp = i*32 + 48
		keystart = binary.BigEndian.Uint64(m.Head[fp : fp+8])
		keyend = binary.BigEndian.Uint64(m.Head[fp+8 : fp+16])
		if string(m.Payload[keystart:keyend]) == key {
			findkey = true
			valend = binary.BigEndian.Uint64(m.Head[fp+24 : fp+32])
			break
		}
	}
	if findkey {
		headlen = headlen - 32
		binary.BigEndian.PutUint64(m.Head[32:40], headlen)

		headleft := m.Head[:fp]
		headright := m.Head[fp+32:]
		tmphead := append([]byte{}, headleft...)
		tmphead = append(tmphead, headright...)
		m.Head = tmphead

		payloadlen := binary.BigEndian.Uint64(m.Head[40:48])
		payloadlen = payloadlen - (valend - keystart)
		binary.BigEndian.PutUint64(m.Head[40:48], payloadlen)

		payloadleft := m.Payload[:keystart]
		payloadright := m.Payload[valend:]
		tmppayload := append([]byte{}, payloadleft...)
		tmppayload = append(tmppayload, payloadright...)
		m.Payload = tmppayload
	}
	return err
}

func NewMsg(val interface{}) (m *Msg, err error) {
	m = new(Msg)
	var mb []byte = []byte{}
	if val != nil {
		switch value := val.(type) {
		case string:
			{
				mb, err = hex.DecodeString(value)
				if err != nil {
					return m, err
				}
			}
		case []byte:
			{
				mb = value
			}
		default:
			return m, errors.New("val type is not []byte/string")
		}
	}
	mblen := len(mb)
	if mblen <= 0 {
		msgidstr := scopeRandomSlowly("hex", 64)
		msgidbyte, _ := hex.DecodeString(msgidstr)
		m.MsgId = msgidstr
		m.Head = msgidbyte
		headlen := make([]byte, 8)
		binary.BigEndian.PutUint64(headlen, 48)
		payloadlen := make([]byte, 8)
		binary.BigEndian.PutUint64(payloadlen, 0)
		m.Head = append(m.Head, headlen...)
		m.Head = append(m.Head, payloadlen...)
	} else {
		if mblen < 48 {
			return m, errors.New("wrong msg block length")
		} else {
			m.MsgId = hex.EncodeToString(mb[:32])
			headlen := binary.BigEndian.Uint64(mb[32:40])
			if headlen < 48 || int64(headlen) > int64(mblen) {
				return m, errors.New("wrong msgblock head")
			}
			m.Head = mb[:headlen]
			payloadlen := binary.BigEndian.Uint64(mb[40:48])
			if int64(payloadlen) > (int64(mblen) - int64(headlen)) {
				return m, errors.New("wrong msgblock payload")
			}
			m.Payload = mb[headlen:(headlen + payloadlen)]
		}
	}
	return m, err
}

func (m *Msg) ToMsgBlock() (mb []byte, err error) {
	err = m.check()
	if err != nil {
		return mb, err
	}
	mb = append([]byte{}, m.Head...)
	mb = append(mb, m.Payload...)
	return mb, err
}

func (m *Msg) Get(key string) (val MsgVal) {
	val = MsgVal{}
	err := m.check()
	if err != nil {
		val.ValErr = err
		return val
	}
	findkey := false
	headlen := binary.BigEndian.Uint64(m.Head[32:40])
	allheaditemlen := headlen - 48
	var keystart uint64
	var keyend uint64
	var valstart uint64
	var valend uint64
	var fp uint64
	var i uint64 = 0
	for i = 0; i < (allheaditemlen)/32; i++ {
		fp = i*32 + 48
		keystart = binary.BigEndian.Uint64(m.Head[fp : fp+8])
		keyend = binary.BigEndian.Uint64(m.Head[fp+8 : fp+16])
		if string(m.Payload[keystart:keyend]) == key {
			findkey = true
			valstart = binary.BigEndian.Uint64(m.Head[fp+16 : fp+24])
			valend = binary.BigEndian.Uint64(m.Head[fp+24 : fp+32])
			break
		}
	}
	if findkey {
		val = parseMsgVal(m.Payload, valstart, valend)
	} else {
		val.ValErr = errors.New("notfound")
	}
	return val
}

func (m *Msg) ToMsgString() (mstr string, err error) {
	mb, err := m.ToMsgBlock()
	if err != nil {
		return "", err
	}
	mstr = hex.EncodeToString(mb)
	return mstr, nil
}

func (m *Msg) ExportFile(fpath string) (err error) {
	mstr, err := m.ToMsgString()
	if err != nil {
		return err
	}
	fm := os.FileMode(0777)
	dir := filepath.Dir(fpath)
	err = os.MkdirAll(dir, fm)
	if err != nil {
		return err
	}
	f1, err := os.Create(fpath)
	defer f1.Close()
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f1, 102400)
	_, err = w.WriteString(mstr)
	w.Flush()
	if err != nil {
		return err
	}
	return nil
}

func ImportMsgFile(fpath string) (msg *Msg, err error) {
	bb, err := ioutil.ReadFile(fpath)
	if err != nil {
		return msg, err
	}
	bb, err = hex.DecodeString(string(bb))
	if err != nil {
		return msg, err
	}
	msg, err = NewMsg(bb)
	return msg, err
}

func (mm MsgMap) ToMsgBlock() (mb []byte, err error) {
	msgid, ok := mm[`MsgId`]
	if !ok {
		return mb, errors.New("no msgid error")
	}
	if len(msgid.ValText) != 64 {
		return mb, errors.New("wrong msgid")
	}
	msgidbytes, err := hex.DecodeString(msgid.ValText)
	if err != nil {
		return mb, errors.New("wrong msgid")
	}
	headlenbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(headlenbytes, 48)
	payloadlenbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(payloadlenbytes, 0)
	mb = append([]byte{}, msgidbytes...)
	mb = append(mb, headlenbytes...)
	mb = append(mb, payloadlenbytes...)
	m, err := NewMsg(mb)
	if err != nil {
		return mb, err
	}
	m.Payload = []byte{}
	var keystart uint64 = 0
	var keyend uint64
	var valstart uint64
	var valend uint64
	var cursor uint64 = 0
	for k, v := range mm {
		if k == "MsgId" {
			continue
		}
		parentchain := []MsgVal{}
		e := v.check(parentchain, mm)
		if e != nil {
			return mb, e
		}
		keybytes := []byte(k)
		keystart = cursor
		keyend = keystart + uint64(len(keybytes))
		valstart = keyend
		valbytes, err := formatMsgVal(v, valstart)
		if err != nil {
			return mb, err
		}
		valend = valstart + uint64(len(valbytes))
		cursor = valend
		headitemkeystart := make([]byte, 8)
		binary.BigEndian.PutUint64(headitemkeystart, keystart)
		headitemkeyend := make([]byte, 8)
		binary.BigEndian.PutUint64(headitemkeyend, keyend)
		headitemvalstart := make([]byte, 8)
		binary.BigEndian.PutUint64(headitemvalstart, valstart)
		headitemvalend := make([]byte, 8)
		binary.BigEndian.PutUint64(headitemvalend, valend)
		headitem := append([]byte{}, headitemkeystart...)
		headitem = append(headitem, headitemkeyend...)
		headitem = append(headitem, headitemvalstart...)
		headitem = append(headitem, headitemvalend...)
		m.Head = append(m.Head, headitem...)
		payloaditem := append([]byte{}, keybytes...)
		payloaditem = append(payloaditem, valbytes...)
		m.Payload = append(m.Payload, payloaditem...)
	}
	headlen := uint64(len(m.Head))
	binary.BigEndian.PutUint64(m.Head[32:40], headlen)
	payloadlen := uint64(len(m.Payload))
	binary.BigEndian.PutUint64(m.Head[40:48], payloadlen)
	mb, err = m.ToMsgBlock()
	return mb, err
}

func NewMsgMap(mb []byte) (mm MsgMap, err error) {
	mm = make(map[string]MsgVal)
	mblen := len(mb)
	if mblen <= 0 {
		msgidstr := scopeRandomSlowly("hex", 64)
		mm[`MsgId`] = MsgVal{ValType: "text", ValText: msgidstr}
	} else {
		m, err := NewMsg(mb)
		if err != nil {
			return mm, err
		}
		err = m.check()
		if err != nil {
			return mm, err
		}
		mm[`MsgId`] = MsgVal{ValType: "text", ValText: m.MsgId}
		headlen := binary.BigEndian.Uint64(m.Head[32:40])
		allheaditemlen := headlen - 48
		var keystart uint64
		var keyend uint64
		var valstart uint64
		var valend uint64
		var fp uint64
		var i uint64 = 0
		for i = 0; i < (allheaditemlen)/32; i++ {
			fp = i*32 + 48
			keystart = binary.BigEndian.Uint64(m.Head[fp : fp+8])
			keyend = binary.BigEndian.Uint64(m.Head[fp+8 : fp+16])
			valstart = binary.BigEndian.Uint64(m.Head[fp+16 : fp+24])
			valend = binary.BigEndian.Uint64(m.Head[fp+24 : fp+32])
			key := string(m.Payload[keystart:keyend])
			val := parseMsgVal(m.Payload, valstart, valend)
			mm[key] = val
		}
	}
	return mm, err
}
