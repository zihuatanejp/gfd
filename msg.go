package gfd

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	crcrand "crypto/rand"
)

type Msg struct {
	MsgId string
	Head []byte
	Payload []byte
}

type MsgVal struct {
	ValType string
	ValText string
	ValByte []byte
	ValList []MsgVal
	ValMap map[string]MsgVal
	ValErr error
}

type MsgMap map[string]MsgVal

func (m *Msg)check()(e error)  {
	if len(m.MsgId)!=64{
		return errors.New("msgid error")
	}
	if len(m.Head)<48{
		return errors.New("wrong msg block length")
	}
	if hex.EncodeToString(m.Head[:32])!=m.MsgId{
		return errors.New("wrong head msgid")
	}
	headlen :=  binary.BigEndian.Uint64(m.Head[32:40])
	payloadlen:= binary.BigEndian.Uint64(m.Head[40:48])
	if int64( headlen) != int64(len(m.Head)){
		return errors.New("wrong head length")
	}
	if int64(payloadlen)!= int64(len( m.Payload)){
		return errors.New("wrong payload length")
	}
	allheaditemlen := headlen-48
	if (headlen-48)%32!=0{
		return  errors.New("wrong head length")
	}
	var keystart uint64
	var keyend uint64
	var valstart uint64
	var valend uint64
	var i uint64 = 0
	for i=0;i<(allheaditemlen)/32;i++{
		fp := 48+i*32
		keystart = binary.BigEndian.Uint64(m.Head[fp:fp+8])
		keyend = binary.BigEndian.Uint64(m.Head[fp+8:fp+16])
		valstart = binary.BigEndian.Uint64(m.Head[fp+16:fp+24])
		valend = binary.BigEndian.Uint64(m.Head[fp+24:fp+32])
		if keyend<keystart{
			return errors.New("msg wrong head key index")
		}
		if valend<valstart{
			return errors.New("msg wrong head val index")
		}
	}
	return e
}

func (m *MsgVal) check(parentchain []MsgVal,mm map[string]MsgVal)(e error){
	if m.ValType =="map"{
		if reflect.DeepEqual(m.ValMap,mm){
			return errors.New("wrong data structure self-referenced")
		}
	}
	switch m.ValType {
	case "list","map":{
		for _,item := range parentchain{
			if reflect.DeepEqual(item,m){
				return errors.New("wrong data structure self-referenced")
			}
		}
		parentchain = append(parentchain,*m)
		if len(m.ValList)>0{
			for _,v:= range m.ValList{
				for _,item := range parentchain{
					if reflect.DeepEqual(item,v){
						return errors.New("wrong data structure self-referenced")
					}
				}
				e = v.check(parentchain,mm)
				if e!=nil{
					return e
				}
			}
		}
		if len(m.ValMap)>0{
			for k,v:= range m.ValMap{
				if k=="MsgId"{
					continue
				}
				for _,item := range parentchain{
					if reflect.DeepEqual(item,v){
						return errors.New("wrong data structure self-referenced")
					}
				}
				e = v.check(parentchain,mm)
				if e!=nil{
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

func genMsgVal(val interface{})(r []byte,e error)  {
	if valtext,ok :=val.(string);ok{
		r = append([]byte{},byte(1))
		r = append(r,[]byte(valtext)...)
	}else if valbyte,ok:= val.([]byte);ok{
		r = append([]byte{},byte(2))
		r = append(r,valbyte...)
	}else{
		return r,errors.New("val type is string/[]byte")
	}
	return r,e
}

func (m *Msg)Set(key string,val interface{}) (err error) {
	err = m.check()
	if err!=nil{
		return err
	}
	findkey := false
	headlen :=  binary.BigEndian.Uint64(m.Head[32:40])
	payloadlen:= binary.BigEndian.Uint64(m.Head[40:48])
	newmsgval,err:=genMsgVal(val)
	if err!=nil{
		return err
	}
	var keystart uint64
	var keyend uint64
	var valstart uint64
	var valend uint64
	var fp uint64
	allheaditemlen := headlen-48
	var i uint64 = 0
	for i=0;i<(allheaditemlen)/32;i++{
		fp = 48+i*32
		keystart = binary.BigEndian.Uint64(m.Head[fp:fp+8])
		keyend = binary.BigEndian.Uint64(m.Head[fp+8:fp+16])
		if string(m.Payload[keystart:keyend])==key{
			findkey =true
			valstart = binary.BigEndian.Uint64(m.Head[fp+16:fp+24])
			valend = binary.BigEndian.Uint64(m.Head[fp+24:fp+32])
			break
		}
	}

	if findkey{
		newmsgvallen := len(newmsgval)
		centerlen := int64(newmsgvallen) - int64(valend-valstart)
		binary.BigEndian.PutUint64(m.Head[fp+24:fp+32],valstart+uint64(len(newmsgval)))
		if centerlen<=0{
			copy( m.Payload[valstart:valend],newmsgval)
		}else{
			left := m.Payload[:valstart]
			right := m.Payload[valend:]
			tmp := append([]byte{},left...)
			tmp = append(tmp,newmsgval...)
			tmp = append(tmp,right...)
			m.Payload = tmp
			binary.BigEndian.PutUint64(m.Head[40:48],payloadlen+uint64(centerlen))
		}
	}else{
		headlen = headlen+32
		binary.BigEndian.PutUint64(m.Head[32:40],headlen )

		newitem := []byte(key)
		keylen:= len(newitem)

		newitem = append(newitem,newmsgval...)
		m.Payload = append(m.Payload,newitem...)
		newitemlen := len(newitem)
		newpayloadlen := payloadlen+ uint64(newitemlen)
		binary.BigEndian.PutUint64(m.Head[40:48],newpayloadlen)
		keystart := make([]byte,8)
		binary.BigEndian.PutUint64(keystart,payloadlen)
		keyend := make([]byte,8)
		binary.BigEndian.PutUint64(keyend,payloadlen+uint64(keylen))
		valend := make([]byte,8)
		binary.BigEndian.PutUint64(valend,newpayloadlen)
		newheaditem := append([]byte{},keystart...)
		newheaditem = append(newheaditem,keyend...)
		newheaditem = append(newheaditem,keyend...)
		newheaditem = append(newheaditem,valend...)
		m.Head = append(m.Head,newheaditem...)
	}
	return err
}

func (m *Msg)Remove(key string)(err error){
	err = m.check()
	if err!=nil{
		return err
	}
	findkey := false
	headlen :=  binary.BigEndian.Uint64(m.Head[32:40])
	allheaditemlen := headlen-48
	var keystart uint64
	var keyend uint64
	var valend uint64
	var fp uint64
	var i uint64 = 0
	for i=0;i<(allheaditemlen)/32;i++{
		fp = i*32+48
		keystart = binary.BigEndian.Uint64(m.Head[fp:fp+8])
		keyend = binary.BigEndian.Uint64(m.Head[fp+8:fp+16])
		if string(m.Payload[keystart:keyend])==key{
			findkey =true
			valend = binary.BigEndian.Uint64(m.Head[fp+24:fp+32])
			break
		}
	}
	if findkey{
		headlen = headlen-32
		binary.BigEndian.PutUint64(m.Head[32:40],headlen )

		headleft := m.Head[:fp]
		headright := m.Head[fp+32:]
		tmphead := append([]byte{},headleft...)
		tmphead = append(tmphead,headright...)
		m.Head = tmphead

		payloadlen:= binary.BigEndian.Uint64(m.Head[40:48])
		payloadlen = payloadlen -(valend-keystart)
		binary.BigEndian.PutUint64(m.Head[40:48],payloadlen )

		payloadleft:= m.Payload[:keystart]
		payloadright:= m.Payload[valend:]
		tmppayload := append([]byte{},payloadleft...)
		tmppayload = append(tmppayload,payloadright...)
		m.Payload = tmppayload
	}
	return err
}

func NewMsg(mb []byte) (m *Msg,err error)  {
	m = new(Msg)
	mblen :=len(mb)
	if mblen<=0 {
		msgidstr := scopeRandomSlowly("hex",64)
		msgidbyte,_ := hex.DecodeString(msgidstr)
		m.MsgId = msgidstr
		m.Head = msgidbyte
		headlen := make([]byte,8)
		binary.BigEndian.PutUint64(headlen,48)
		payloadlen:= make([]byte,8)
		binary.BigEndian.PutUint64(payloadlen,0)
		m.Head = append(m.Head,headlen...)
		m.Head = append(m.Head,payloadlen...)
	}else{
		if mblen<48{
			return m,errors.New("wrong msg block length")
		}else{
			m.MsgId = hex.EncodeToString(mb[:32])
			headlen := binary.BigEndian.Uint64(mb[32:40])
			if headlen<48 || int64(headlen)> int64(mblen){
				return m,errors.New("wrong msgblock head")
			}
			m.Head = mb[:headlen]
			payloadlen:= binary.BigEndian.Uint64(mb[40:48])
			if int64(payloadlen)>( int64(mblen)-int64(headlen)){
				return m,errors.New("wrong msgblock payload")
			}
			m.Payload = mb[headlen:(headlen+payloadlen)]
		}
	}
	return m,err
}