package scanner

import "goversion/models"

type netflowRecordNoEasyJSON models.NetflowRecord

func appendNetflowRecordSlice(dst []models.NetflowRecord, src []netflowRecordNoEasyJSON) []models.NetflowRecord {
	for _, r := range src {
		dst = append(dst, models.NetflowRecord(r))
	}
	return dst
}
