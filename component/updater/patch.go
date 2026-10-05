package updater

var (
	GeoUpdateHook func(geoType string, updating bool, skipped bool, updateErr error)
)

func sendGeoUpdateStatus(geoType string, updating bool, skipped bool, updateErr error) {
	if GeoUpdateHook != nil {
		GeoUpdateHook(geoType, updating, skipped, updateErr)
	}
}

// RegisterGeoUpdaterWithCancel is kept for hosts that call the older entry
// point; RegisterGeoUpdater owns the ticker lifecycle and stops any previous
// generation itself.
func RegisterGeoUpdaterWithCancel() {
	RegisterGeoUpdater()
}
