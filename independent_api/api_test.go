package resource_test
import("context";"testing";"github.com/metacubex/mihomo/common/utils";"github.com/metacubex/mihomo/component/resource";P "github.com/metacubex/mihomo/constant/provider")
type independentLegacyVehicle struct{}
func(independentLegacyVehicle)Read(context.Context,utils.HashType)([]byte,utils.HashType,error){return nil,utils.HashType{},nil}
func(independentLegacyVehicle)Write([]byte)error{return nil}
func(independentLegacyVehicle)Path()string{return "unused"}
func(independentLegacyVehicle)Url()string{return "legacy://api"}
func(independentLegacyVehicle)Proxy()string{return ""}
func(independentLegacyVehicle)Type()P.VehicleType{return P.File}
func TestIndependentLegacyVehicleSourceCompatibility(t *testing.T){f:=resource.NewFetcher("legacy",0,independentLegacyVehicle{},nil,func([]byte)(string,error){return "",nil},nil);_=f.Close()}
