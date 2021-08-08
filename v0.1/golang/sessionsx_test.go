package sessionslx

import (
	"net/http"
	"testing"

	jwtx "github.com/herebythere/jwtx/v0.1/golang"
)

const (
	increment                    = "INCR"
	testJSONIncrement            = "test_json_increment"
	testPerson                   = "test_person"
	testLocalSessions            = "local_sessions_test"
	testLocalSessionsBadAudChunk = "local_sessions_test_invalid_chunk"

	tmk3 = "tmk3"
)

var (
	jwtxParamsTest = jwtx.CreateJWTParams{
		Aud:      []string{testLocalSessions},
		Iss:      tmk3,
		Sub:      testPerson,
		Lifetime: 3600,
	}
	tokenPayloadTest, errTokenPayloadTest = jwtx.CreateJWT(&jwtxParamsTest, nil)
	lateDelay                             = int64(60)
	lateJwtxPayloadTest                   = jwtx.CreateJWTParams{
		Aud:      []string{testLocalSessions},
		Delay:    &lateDelay,
		Iss:      tmk3,
		Sub:      testPerson,
		Lifetime: 3600,
	}
	lateTokenPayloadTest, errLateTokenPayloadTest = jwtx.CreateJWT(&lateJwtxPayloadTest, nil)
	expiredTokenPayloadTest                       = jwtx.CreateJWTParams{
		Aud:      []string{testLocalSessions},
		Iss:      tmk3,
		Sub:      testPerson,
		Lifetime: 0,
	}
	expiredTokenPayload, errExpiredTokenPayload = jwtx.CreateJWT(&expiredTokenPayloadTest, nil)
)

func TestPostJSONRequest(t *testing.T) {
	instructions := []interface{}{increment, testJSONIncrement}
	resp, errResp := postJSONRequest(instructions)
	if errResp != nil {
		t.Fail()
		t.Logf(errResp.Error())
	}
	if resp == nil {
		t.Fail()
		t.Logf("set service was not successfuul")
	}
	if resp != nil && resp.StatusCode != http.StatusOK {
		t.Fail()
		t.Logf("response code was not 200")
	}
}

func TestSetSession(t *testing.T) {
	if errTokenPayloadTest != nil {
		t.Fail()
		t.Logf(errTokenPayloadTest.Error())
	}

	setSuccessful, errSetSuccessful := setSession(testLocalSessions, tokenPayloadTest)
	if !setSuccessful {
		t.Fail()
		t.Logf("set service was not successfuul")
	}
	if errSetSuccessful != nil {
		t.Fail()
		t.Logf(errSetSuccessful.Error())
	}
}

func TestCreateSession(t *testing.T) {
	errTokenPayload := CreateSession(testLocalSessions, &jwtxParamsTest, nil)
	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestValidateTokenWindowAndAud(t *testing.T) {
	tokenIsValidWindow, errTokenPayload := validateTokenWindowAndAud(tokenPayloadTest.Token, testLocalSessions, nil)
	if !tokenIsValidWindow {
		t.Fail()
		t.Logf("token window is not valid")
	}
	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestInvalidTokenWindowAndAud(t *testing.T) {
	tokenIsValidWindow, errTokenPayload := validateTokenWindowAndAud(lateTokenPayloadTest.Token, testLocalSessions, nil)
	if tokenIsValidWindow {
		t.Fail()
		t.Logf("token window should not be valid")
	}
	if errTokenPayload == nil {
		t.Fail()
		t.Logf("there should be an error about the used before expected time")
	}
}

func TestExpiredTokenWindowAndAud(t *testing.T) {
	tokenIsValidWindow, errTokenPayload := validateTokenWindowAndAud(expiredTokenPayload.Token, testLocalSessions, nil)
	if tokenIsValidWindow {
		t.Fail()
		t.Logf("token window should be expired")
	}
	if errTokenPayload == nil {
		t.Fail()
		t.Logf("there should be an error about the used before expected time")
	}
}

func TestInvalidTokenWindowAndInvalidAud(t *testing.T) {
	tokenIsValidWindow, errTokenPayload := validateTokenWindowAndAud(tokenPayloadTest.Token, testLocalSessionsBadAudChunk, nil)
	if tokenIsValidWindow {
		t.Fail()
		t.Logf("token aud chunk is not valid but still passed")
	}
	if errTokenPayload == nil {
		t.Fail()
		t.Logf("there should be an associated error with an invalid aud chunk")
	}
}

func TestVerifySession(t *testing.T) {
	verified, errVerified := VerifySession(
		testLocalSessions,
		*tokenPayloadTest.Token,
		testLocalSessions,
	)
	if !verified {
		t.Fail()
		t.Logf("verify skeleton key was not successfuul")
	}
	if errVerified != nil {
		t.Fail()
		t.Logf(errVerified.Error())
	}
}
