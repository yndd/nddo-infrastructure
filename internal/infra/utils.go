package infra

import (
	"encoding/json"

	"github.com/yndd/nddo-grpc/resource/resourcepb"
)

// GetValue return the data of the gnmi typed value
func GetValue(updValue *resourcepb.TypedValue) (interface{}, error) {
	if updValue == nil {
		return nil, nil
	}
	var value interface{}
	var jsondata []byte
	switch updValue.Value.(type) {
	case *resourcepb.TypedValue_AsciiVal:
		value = updValue.GetAsciiVal()
	case *resourcepb.TypedValue_BoolVal:
		value = updValue.GetBoolVal()
	case *resourcepb.TypedValue_BytesVal:
		value = updValue.GetBytesVal()
	case *resourcepb.TypedValue_DecimalVal:
		value = updValue.GetDecimalVal()
	case *resourcepb.TypedValue_FloatVal:
		value = updValue.GetFloatVal()
	case *resourcepb.TypedValue_IntVal:
		value = updValue.GetIntVal()
	case *resourcepb.TypedValue_StringVal:
		value = updValue.GetStringVal()
	case *resourcepb.TypedValue_UintVal:
		value = updValue.GetUintVal()
	case *resourcepb.TypedValue_JsonIetfVal:
		jsondata = updValue.GetJsonIetfVal()
	case *resourcepb.TypedValue_JsonVal:
		jsondata = updValue.GetJsonVal()
	case *resourcepb.TypedValue_LeaflistVal:
		value = updValue.GetLeaflistVal()
	case *resourcepb.TypedValue_ProtoBytes:
		value = updValue.GetProtoBytes()
	case *resourcepb.TypedValue_AnyVal:
		value = updValue.GetAnyVal()
	}
	if value == nil && len(jsondata) != 0 {
		err := json.Unmarshal(jsondata, &value)
		if err != nil {
			return nil, err
		}
	}
	return value, nil
}
