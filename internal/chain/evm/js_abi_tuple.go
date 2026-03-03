package evm

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/grafana/sobek"
)

// exportTypesSpecs exports the first argument as []interface{} where each element is either
// a string (e.g. "address", "uint256") or a tuple spec map: { type: "tuple", components: [ { name, type } | { type: "tuple", components: [...] }, ... ] }.
func exportTypesSpecs(v sobek.Value) ([]interface{}, bool) {
	if v == nil || v.Equals(sobek.Undefined()) {
		return nil, false
	}
	ex := v.Export()
	sl, ok := ex.([]interface{})
	if !ok {
		return nil, false
	}
	return sl, true
}

// typesToArgumentsFromSpecs builds abi.Arguments from type specs (string or tuple map).
func typesToArgumentsFromSpecs(specs []interface{}) (abi.Arguments, error) {
	args := make(abi.Arguments, 0, len(specs))
	for _, s := range specs {
		arg, err := typeSpecToArgument(s)
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
	}
	return args, nil
}

func typeSpecToArgument(spec interface{}) (abi.Argument, error) {
	switch v := spec.(type) {
	case string:
		typ, err := abi.NewType(v, "", nil)
		if err != nil {
			return abi.Argument{}, err
		}
		return abi.Argument{Name: "", Type: typ}, nil
	case map[string]interface{}:
		if v["type"] != "tuple" {
			return abi.Argument{}, fmt.Errorf("unsupported type spec: %v", v["type"])
		}
		compIf, ok := v["components"]
		if !ok {
			return abi.Argument{}, fmt.Errorf("tuple spec missing components")
		}
		compSl, ok := compIf.([]interface{})
		if !ok {
			return abi.Argument{}, fmt.Errorf("tuple components must be array")
		}
		components, err := marshalComponents(compSl)
		if err != nil {
			return abi.Argument{}, err
		}
		typ, err := abi.NewType("tuple", "", components)
		if err != nil {
			return abi.Argument{}, err
		}
		return abi.Argument{Name: "", Type: typ}, nil
	default:
		return abi.Argument{}, fmt.Errorf("type spec must be string or tuple object")
	}
}

func marshalComponents(compSl []interface{}) ([]abi.ArgumentMarshaling, error) {
	out := make([]abi.ArgumentMarshaling, 0, len(compSl))
	for _, c := range compSl {
		m, ok := c.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("component must be object")
		}
		name, _ := m["name"].(string)
		typeStr, _ := m["type"].(string)
		if typeStr == "" {
			return nil, fmt.Errorf("component missing type")
		}
		am := abi.ArgumentMarshaling{Name: name, Type: typeStr, InternalType: typeStr}
		if typeStr == "tuple" || typeStr == "tuple[]" {
			subIf, ok := m["components"]
			if !ok {
				return nil, fmt.Errorf("tuple component missing components")
			}
			subSl, ok := subIf.([]interface{})
			if !ok {
				return nil, fmt.Errorf("tuple components must be array")
			}
			subComp, err := marshalComponents(subSl)
			if err != nil {
				return nil, err
			}
			am.Components = subComp
		}
		out = append(out, am)
	}
	return out, nil
}

// convertValueForPack converts a JS value to the Go type expected by abi.Type.Pack (handles tuple → struct).
func convertValueForPack(typ abi.Type, val interface{}) (interface{}, error) {
	if typ.T == abi.TupleTy {
		return tupleValueToStruct(typ, val)
	}
	// scalar: use string type for jsValueToAbiArg
	typeStr := typ.String()
	if typeStr[0] == '(' {
		typeStr = "tuple"
	}
	return jsValueToAbiArg(typeStr, val)
}

func tupleValueToStruct(typ abi.Type, val interface{}) (interface{}, error) {
	// val is map[string]interface{} (object) or []interface{} (array)
	var fieldVals []interface{}
	switch v := val.(type) {
	case map[string]interface{}:
		fieldVals = make([]interface{}, len(typ.TupleRawNames))
		for i, name := range typ.TupleRawNames {
			if f, ok := v[name]; ok {
				fieldVals[i] = f
			} else {
				// try camelCase
				camel := toCamelCase(name)
				if f, ok := v[camel]; ok {
					fieldVals[i] = f
				}
			}
		}
	case []interface{}:
		if len(v) < len(typ.TupleRawNames) {
			return nil, fmt.Errorf("tuple value array too short")
		}
		fieldVals = v[:len(typ.TupleRawNames)]
	default:
		return nil, fmt.Errorf("tuple value must be object or array")
	}

	structVal := reflect.New(typ.GetType()).Elem()
	for i, elem := range typ.TupleElems {
		goVal, err := convertValueForPack(*elem, fieldVals[i])
		if err != nil {
			return nil, err
		}
		field := structVal.Field(i)
		field.Set(reflect.ValueOf(goVal))
	}
	return structVal.Interface(), nil
}

func toCamelCase(s string) string {
	if s == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

// abiStructToMap converts a struct (from UnpackValues tuple) to map for JS (keys = original ABI names).
func abiStructToMap(v interface{}) map[string]interface{} {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil
	}
	out := make(map[string]interface{})
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		name := typ.Field(i).Name
		// json tag often has original name
		if tag := typ.Field(i).Tag.Get("json"); tag != "" && tag != "-" {
			name = strings.TrimSuffix(tag, ",omitempty")
		} else {
			// export as lowercase first letter for JS
			r, n := utf8.DecodeRuneInString(name)
			name = string(unicode.ToLower(r)) + name[n:]
		}
		out[name] = abiValueToJS(field.Interface())
	}
	return out
}
