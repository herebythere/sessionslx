package sessionslx

import (
	"os"
	"testing"

	jwtx "github.com/herebythere/jwtx/v0.1/golang"
)

const (
	increment         = "INCR"
	testPerson        = "test_person"
	testLocalSessions = "local_sessions_test"
	testIss           = "testIss"
)

var (
	localCacheAddress = os.Getenv("LOCAL_CACHE_ADDRESS")
	// localCacheAddress = "http://10.88.0.1:1234"
)

var (
	jwtxParamsTest = CreateSessionParams{
		Aud:      []string{testLocalSessions},
		Iss:      testIss,
		Sub:      testPerson,
		Lifetime: 3600,
	}
	tokenPayloadTest, errTokenPayloadTest = jwtx.CreateJWT(
		&jwtxParamsTest,
		nil,
	)
	lateDelay           = int64(60)
	lateJwtxPayloadTest = CreateSessionParams{
		Aud:      []string{testLocalSessions},
		Delay:    &lateDelay,
		Iss:      testIss,
		Sub:      testPerson,
		Lifetime: 3600,
	}
	lateTokenPayloadTest, errLateTokenPayloadTest = jwtx.CreateJWT(
		&lateJwtxPayloadTest,
		nil,
	)
	expiredTokenPayloadTest = CreateSessionParams{
		Aud:      []string{testLocalSessions},
		Iss:      testIss,
		Sub:      testPerson,
		Lifetime: 0,
	}
	expiredTokenPayload, errExpiredTokenPayload = jwtx.CreateJWT(
		&expiredTokenPayloadTest,
		nil,
	)
)

func TestSetSession(t *testing.T) {
	if errTokenPayloadTest != nil {
		t.Fail()
		t.Logf(errTokenPayloadTest.Error())
	}

	setSuccessful, errSetSuccessful := setSession(
		localCacheAddress,
		testLocalSessions,
		tokenPayloadTest,
		60,
	)
	if !setSuccessful {
		t.Fail()
		t.Logf("set session token was not successfuul")
	}
	if errSetSuccessful != nil {
		t.Fail()
		t.Logf(errSetSuccessful.Error())
	}
}

func TestCreateSession(t *testing.T) {
	errTokenPayload := CreateSession(
		localCacheAddress,
		testLocalSessions,
		&jwtxParamsTest,
	)
	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestVerifySession(t *testing.T) {
	verified, errVerified := VerifySession(
		localCacheAddress,
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
