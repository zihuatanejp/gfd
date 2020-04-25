# gfd
gfd(go flat data) serialization for Go.文字，二进制字节，结构体，映射数据的序列化和反序列化方案。  


This package provides a simple way to Marshal or unmarshal  structured data by one line of code.   
you can export structured data output to a file,  
when you need this structed data ,just import it back.

It support any level of nested & structured data.

It support marshal/unmarshal data format: []byte or hex-utf8-string.  
It originally designed for the communication protocol on TCP/UDP protocol,  
but obviously it can also be used in other places.

It's lightweight, unlike flatbuffer or protocol buffers,  
This package has a very small amount of code.  
it's schema-less (self-describing) type. 
use these data like a dynamically typed languages way.  


Run more efficiently than JSON without reflection.  

you can use it to store  data of several GB. 

just like json's  advantage,   
i think it is  a better choice for systems that have very little to no information ahead of time about what data needs to be stored.

## Quick Start  
```go
msg,err :=NewMsg(nil)   

msg.Set("abc","123")
msg.Set("test",[]byte("床前明月光"))
// the set method supports adding or modifying the specified key value pair data.
// key is string, value can be string/[]byte.
// the set method does not support nested settings or nested data,
// you can set those data by construct nested  "type MsgVal"  by yourself

msg.Remove("abc") 

msgval := msg.Get("test")
println(string(msgval.ValByte)) // "床前明月光"
/* 
the get method return a "type MsgVal" data,
type MsgVal struct {
    ValType string        // "text"/"byte"/"list"/"map"
    ValText string        // if ValType is "text", this field will be set
    ValByte []byte       // if ValType is "byte",this field will be set
    ValList []MsgVal   // if  ValType is "list", this field will be set, it can be nested
    ValMap map[string]MsgVal // if  ValType is "map", this field will be set,it can be nested
    ValErr error // if any err occurred,this field will be set.
}
*/


mb,err := msg.ToMsgBlock() 
// return Marshaled data, format: []byte

mstr,err:= msg.ToMsgString()
// return Marshaled data, format: string

msg,err :=NewMsg(mb)  
// the NewMsg method parameter can be []byte or string.

msg.ExportFile(`C:\app\mpack.txt`)
// output data to a file, file content will be overwrite, if file not exist,will be create and write.

msg,err := ImportMsgFile(`C:\app\mpack.txt`)
// import it back

//How to Set nested data ?
// eg data like this:
m5:=NewMsgMap(nil)
m1 := MsgVal{ValType:"text",ValText:"aaaaaa"}
m2 := MsgVal{ValType:"text",ValText:"bbbbb"}
m3 := []Msgval{m1,m2}
m5["k1"] = MsgVal{ValType:"text",ValText:"a1"}
m5["m3"] = MsgVal{ValType:"list",ValList:m3}

mb,err:=m5.ToMsgBlock()  // just by one line of code

// how to get all structed data from a MsgBlock ?
msgmap,err:= NewMsgMap(mb) // just by one line of code


```