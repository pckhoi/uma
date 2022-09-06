package urlencode

import (
	"fmt"
	"net/url"
	"reflect"
)

func fieldName(field reflect.StructField) string {
	if !field.IsExported() {
		return ""
	}
	if s := field.Tag.Get("url"); s == "-" {
		return ""
	} else if s != "" {
		return s
	}
	newName := []byte{}
	for i, c := range field.Name {
		if c >= 65 && c <= 90 {
			if i == 0 {
				newName = append(newName, byte(c+32))
			} else {
				newName = append(newName, '_', byte(c+32))
			}
		} else {
			newName = append(newName, byte(c))
		}
	}
	return string(newName)
}

func serializeFieldValue(v reflect.Value) ([]string, error) {
	if v.IsZero() {
		return nil, nil
	}
	switch v.Kind() {
	case reflect.String:
		return []string{v.String()}, nil
	case reflect.Int:
		return []string{fmt.Sprintf("%d", v.Int())}, nil
	case reflect.Bool:
		return []string{fmt.Sprintf("%v", v.Bool())}, nil
	case reflect.Slice:
		rslt := []string{}
		elemKind := v.Type().Elem().Kind()
		switch elemKind {
		case reflect.String:
			for i := 0; i < v.Len(); i++ {
				rslt = append(rslt, v.Index(i).String())
			}
		case reflect.Int:
			for i := 0; i < v.Len(); i++ {
				rslt = append(rslt, fmt.Sprintf("%d", v.Index(i).Int()))
			}
		case reflect.Bool:
			for i := 0; i < v.Len(); i++ {
				rslt = append(rslt, fmt.Sprintf("%v", v.Index(i).Bool()))
			}
		default:
			return nil, fmt.Errorf("unhandled slice of %v", elemKind)
		}
		return rslt, nil
	case reflect.Pointer:
		elem := v.Elem()
		elemKind := v.Type().Elem().Kind()
		switch elemKind {
		case reflect.String:
			return []string{elem.String()}, nil
		case reflect.Int:
			return []string{fmt.Sprintf("%d", elem.Int())}, nil
		case reflect.Bool:
			return []string{fmt.Sprintf("%v", elem.Bool())}, nil
		default:
			return nil, fmt.Errorf("unhandled slice of %v", elemKind)
		}
	default:
		return nil, fmt.Errorf("unhandled %v", v.Kind())
	}
}

func ToValues(obj interface{}) (*url.Values, error) {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("obj must be a struct or a pointer to struct")
	}
	numField := v.NumField()
	values := &url.Values{}
	for i := 0; i < numField; i++ {
		structField := v.Type().FieldByIndex([]int{i})
		fieldName := fieldName(structField)
		if fieldName == "" {
			continue
		}
		sl, err := serializeFieldValue(v.FieldByIndex([]int{i}))
		if err != nil {
			return nil, fmt.Errorf("error serializing field %q: %v", structField.Name, err)
		}
		if sl != nil {
			(*values)[fieldName] = sl
		}
	}
	return values, nil
}
