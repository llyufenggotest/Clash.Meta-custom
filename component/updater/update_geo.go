package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/sync/errgroup"
)

var (
	autoUpdate     bool
	updateInterval int
	geoUpdaterMu   sync.Mutex
	geoUpdaterID   uint64
	geoUpdaterStop context.CancelFunc

	updatingGeo atomic.Bool
)

func GeoAutoUpdate() bool {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()
	return autoUpdate
}

func GeoUpdateInterval() int {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()
	return updateInterval
}

func SetGeoAutoUpdate(newAutoUpdate bool) {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()
	autoUpdate = newAutoUpdate
}

func SetGeoUpdateInterval(newGeoUpdateInterval int) {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()
	updateInterval = newGeoUpdateInterval
}

func UpdateMMDB() (err error) {
	sendGeoUpdateStatus("MMDB", true, false, nil)
	var skipped bool
	defer func() { sendGeoUpdateStatus("MMDB", false, skipped, err) }()

	vehicle := resource.NewHTTPVehicle(geodata.MmdbUrl(), C.Path.MMDB(), "", nil, defaultHttpTimeout, 0)
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return fmt.Errorf("can't download MMDB database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		skipped = true
		// refresh mtime so the next apply's update check won't re-trigger
		_ = os.Chtimes(vehicle.Path(), time.Now(), time.Now())
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download MMDB database file: no data")
	}

	instance, err := maxminddb.FromBytes(data)
	if err != nil {
		return fmt.Errorf("invalid MMDB database file: %s", err)
	}
	_ = instance.Close()

	defer mmdb.ReloadIP()
	mmdb.IPInstance().Reader.Close() //  mmdb is loaded with mmap, so it needs to be closed before overwriting the file
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save MMDB database file: %w", err)
	}
	return nil
}

func UpdateASN() (err error) {
	sendGeoUpdateStatus("ASN", true, false, nil)
	var skipped bool
	defer func() { sendGeoUpdateStatus("ASN", false, skipped, err) }()

	vehicle := resource.NewHTTPVehicle(geodata.ASNUrl(), C.Path.ASN(), "", nil, defaultHttpTimeout, 0)
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return fmt.Errorf("can't download ASN database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		skipped = true
		// refresh mtime so the next apply's update check won't re-trigger
		_ = os.Chtimes(vehicle.Path(), time.Now(), time.Now())
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download ASN database file: no data")
	}

	instance, err := maxminddb.FromBytes(data)
	if err != nil {
		return fmt.Errorf("invalid ASN database file: %s", err)
	}
	_ = instance.Close()

	defer mmdb.ReloadASN()
	mmdb.ASNInstance().Reader.Close() //  mmdb is loaded with mmap, so it needs to be closed before overwriting the file
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save ASN database file: %w", err)
	}
	return nil
}

func UpdateGeoIp() (err error) {
	sendGeoUpdateStatus("GEOIP", true, false, nil)
	var skipped bool
	defer func() { sendGeoUpdateStatus("GEOIP", false, skipped, err) }()

	geoLoader, err := geodata.GetGeoDataLoader("standard")

	vehicle := resource.NewHTTPVehicle(geodata.GeoIpUrl(), C.Path.GeoIP(), "", nil, defaultHttpTimeout, 0)
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return fmt.Errorf("can't download GeoIP database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		skipped = true
		// refresh mtime so the next apply's update check won't re-trigger
		_ = os.Chtimes(vehicle.Path(), time.Now(), time.Now())
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download GeoIP database file: no data")
	}

	if _, err = geoLoader.LoadIPByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoIP database file: %s", err)
	}

	defer geodata.ClearGeoIPCache()
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save GeoIP database file: %w", err)
	}
	return nil
}

func UpdateGeoSite() (err error) {
	sendGeoUpdateStatus("GEOSITE", true, false, nil)
	var skipped bool
	defer func() { sendGeoUpdateStatus("GEOSITE", false, skipped, err) }()

	geoLoader, err := geodata.GetGeoDataLoader("standard")

	vehicle := resource.NewHTTPVehicle(geodata.GeoSiteUrl(), C.Path.GeoSite(), "", nil, defaultHttpTimeout, 0)
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return fmt.Errorf("can't download GeoSite database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		skipped = true
		// refresh mtime so the next apply's update check won't re-trigger
		_ = os.Chtimes(vehicle.Path(), time.Now(), time.Now())
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download GeoSite database file: no data")
	}

	if _, err = geoLoader.LoadSiteByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoSite database file: %s", err)
	}

	defer geodata.ClearGeoSiteCache()
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save GeoSite database file: %w", err)
	}
	return nil
}

func updateGeoDatabases() error {
	defer runtime.GC()

	b := errgroup.Group{}

	if geodata.GeoIpEnable() {
		if geodata.GeodataMode() {
			b.Go(UpdateGeoIp)
		} else {
			b.Go(UpdateMMDB)
		}
	}

	if geodata.ASNEnable() {
		b.Go(UpdateASN)
	}

	if geodata.GeoSiteEnable() {
		b.Go(UpdateGeoSite)
	}

	return b.Wait()
}

var ErrGetDatabaseUpdateSkip = errors.New("GEO database is updating, skip")

func UpdateGeoDatabases() error {
	log.Infoln("[GEO] Start updating GEO database")

	if updatingGeo.Load() {
		return ErrGetDatabaseUpdateSkip
	}

	updatingGeo.Store(true)
	defer updatingGeo.Store(false)

	log.Infoln("[GEO] Updating GEO database")

	if err := updateGeoDatabases(); err != nil {
		log.Errorln("[GEO] update GEO database error: %s", err.Error())
		return err
	}

	return nil
}

func getUpdateTime() (time time.Time, err error) {
	filesToCheck := []string{
		C.Path.GeoIP(),
		C.Path.MMDB(),
		C.Path.ASN(),
		C.Path.GeoSite(),
	}

	for _, file := range filesToCheck {
		var fileInfo os.FileInfo
		fileInfo, err = os.Stat(file)
		if err == nil {
			return fileInfo.ModTime(), nil
		}
	}

	return
}

func RegisterGeoUpdater() {
	geoUpdaterMu.Lock()
	stopGeoUpdaterLocked()
	if !autoUpdate {
		geoUpdaterMu.Unlock()
		return
	}
	if updateInterval <= 0 {
		interval := updateInterval
		geoUpdaterMu.Unlock()
		log.Errorln("[GEO] Invalid update interval: %d", interval)
		return
	}
	interval := updateInterval
	ctx, cancel := context.WithCancel(context.Background())
	geoUpdaterID++
	id := geoUpdaterID
	geoUpdaterStop = cancel
	geoUpdaterMu.Unlock()

	go func() {
		defer func() {
			geoUpdaterMu.Lock()
			if geoUpdaterID == id {
				geoUpdaterStop = nil
			}
			geoUpdaterMu.Unlock()
		}()
		ticker := time.NewTicker(time.Duration(interval) * time.Hour)
		defer ticker.Stop()

		lastUpdate, err := getUpdateTime()
		if err != nil {
			log.Errorln("[GEO] Get GEO database update time error: %s", err.Error())
		} else {
			log.Infoln("[GEO] last update time %s", lastUpdate)
		}
		if err == nil && lastUpdate.Add(time.Duration(interval)*time.Hour).Before(time.Now()) {
			log.Infoln("[GEO] Database has not been updated for %v, update now", time.Duration(interval)*time.Hour)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Infoln("[GEO] updating database every %d hours", interval)
				if err := UpdateGeoDatabases(); err != nil {
					log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				}
			}
		}
	}()
}

func StopGeoUpdater() {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()
	stopGeoUpdaterLocked()
}

func stopGeoUpdaterLocked() {
	geoUpdaterID++
	if geoUpdaterStop != nil {
		geoUpdaterStop()
		geoUpdaterStop = nil
	}
}
