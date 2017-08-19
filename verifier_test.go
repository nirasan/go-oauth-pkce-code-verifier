package go_oauth_pkce_code_verifier

import (
	"regexp"
	"testing"
)

func TestCreateCodeVerifier(t *testing.T) {
	v, e := CreateCodeVerifier()
	if e != nil {
		t.Error(e)
	}
	testCodeVerifire(t, v)
}

func testCodeVerifire(t *testing.T, v *CodeVerifier) {
	if len(v.Value) < 43 || len(v.Value) > 128 {
		t.Errorf("invalid length: %v", v)
	}
	if _, e := regexp.Match(`[a-zA-Z\-\_\.\~]+`, []byte(v.Value)); e != nil {
		t.Errorf("invalid pattern: %v", v)
	}
	t.Logf("%v", v)
}

func TestCreateCodeVerifierWithLength(t *testing.T) {
	for i := 1; i <= 128; i++ {
		v, e := CreateCodeVerifierWithLength(i)
		t.Logf("# length: %d", i)
		if i < MinLength || i > MaxLength {
			if e == nil {
				t.Errorf("invalit result: %v, %v", v, e)
			}
		} else {

			testCodeVerifire(t, v)
		}
	}
}

func TestCreateCodeVerifierFromBytes(t *testing.T) {
	v, e := CreateCodeVerifierFromBytes([]byte{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
		187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
		132, 141, 121})
	if e != nil {
		t.Error(e)
	}
	if v.Value != "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" {
		t.Errorf("invalid code_verifier: %v", v)
	}
	t.Logf("%v", v)
}

// via https://tools.ietf.org/html/rfc7636#appendix-B
func TestCodeVerifier_CodeChallengeS256(t *testing.T) {
	v, _ := CreateCodeVerifier()
	v.Value = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	c := v.CodeChallengeS256()
	if c != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("invalid code_challenge value: %v", c)
	}
	t.Logf("%v, %v", v, c)
}
