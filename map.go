package zgtools

import "sort"

// SortMapKeys 对 map 的键进行排序，包括嵌套的对象和数组
func SortMapKeys(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		sortedMap := make(map[string]interface{})
		for _, key := range keys {
			sortedMap[key] = SortMapKeys(v[key])
		}
		return sortedMap

	case []interface{}:
		sortedArray := make([]interface{}, len(v))
		for i, item := range v {
			sortedArray[i] = SortMapKeys(item)
		}
		return sortedArray

	default:
		return v
	}
}
