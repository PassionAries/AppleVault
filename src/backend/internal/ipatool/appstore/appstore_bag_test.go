package appstore

import (
	gohttp "net/http"
	"net/http/cookiejar"
	"testing"
)

func TestBagCanonicalizesOnlyValidatedAuthenticationURLs(t *testing.T) {
	for _, scenario := range []struct{ endpoint, want string }{
		{fixtureAuthEndpoint, fixtureAuthEndpoint + "/"},
		{fixtureAuthEndpoint + "/", fixtureAuthEndpoint + "/"},
		{"https://p34-buy.itunes.apple.com" + PrivateAppStoreAPIPathAuth + "?route=fixture", "https://p34-buy.itunes.apple.com" + PrivateAppStoreAPIPathAuth + "/?route=fixture"},
		{"https://example.invalid" + PrivateAppStoreAPIPathAuth, ""},
	} {
		t.Run(scenario.endpoint, func(t *testing.T) {
			jar, _ := cookiejar.New(nil)
			store := NewAppStore(Args{Machine: loginFixtureMachine{}, CookieJar: authenticationTestCookieJar{jar}, Transport: authenticationTestTransport(func(r *gohttp.Request) (*gohttp.Response, error) {
				bag := loginFixtureBag()
				bag["urlBag"].(map[string]any)["authenticateAccount"] = scenario.endpoint
				return loginFixtureResponse(t, r, 200, bag), nil
			})})
			bag, err := store.Bag(BagInput{})
			if scenario.want == "" {
				if err == nil {
					t.Fatal("an untrusted URL must be rejected before normalization")
				}
				return
			}
			if err != nil || bag.AuthEndpoint != scenario.want || bag.SAPConfig.AuthEndpoint != scenario.want {
				t.Fatalf("canonical authentication route = %q, want %q; err=%v", bag.AuthEndpoint, scenario.want, err)
			}
		})
	}
}
