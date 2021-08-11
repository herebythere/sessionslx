package sessionslx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	jwtx "github.com/herebythere/jwtx/v0.1/golang"
)

const (
	applicationJson = "application/json"
	setCache        = "SET"
	getCache        = "GET"
	expCache        = "EX"
	oneDayInSeconds = 60 * 60 * 24

	unableToWriteToCache = "unable to write jwt to cache"
	sessionTokens        = "session_tokens"
	colonDelimiter       = ":"
)

var (
	errTokenPayloadIsNil   = errors.New("token payload is nil")
	errInstructionsAreNil  = errors.New("instructions are nil")
	errSessionWasNotStored = errors.New("session was not stored")
	errSessionDoesNotExist = errors.New("session does not exist")
)

func getCacheSetID(categories ...string) string {
	return strings.Join(categories, colonDelimiter)
}

func execAndReturnBool(
	cacheAddress string,
	instructions *[]interface{},
) (
	bool,
	error,
) {
	if instructions == nil {
		return false, errInstructionsAreNil
	}

	bodyBytes := new(bytes.Buffer)
	errJson := json.NewEncoder(bodyBytes).Encode(*instructions)
	if errJson != nil {
		return false, errJson
	}

	resp, errResponse := http.Post(cacheAddress, applicationJson, bodyBytes)
	if errResponse != nil {
		return false, errResponse
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, nil
}

func execAndParseTokenPayloadStr(
	cacheAddress string,
	instructions *[]interface{},
) (
	*string,
	error,
) {
	if instructions == nil {
		return nil, errInstructionsAreNil
	}

	bodyBytes := new(bytes.Buffer)
	errJson := json.NewEncoder(bodyBytes).Encode(*instructions)
	if errJson != nil {
		return nil, errJson
	}

	resp, errResp := http.Post(cacheAddress, applicationJson, bodyBytes)
	if errResp != nil {
		return nil, errResp
	}
	defer resp.Body.Close()

	var tokenPayloadAsBase64 string
	errJSONResponse := json.NewDecoder(resp.Body).Decode(&tokenPayloadAsBase64)
	if errJSONResponse != nil {

		return nil, errJSONResponse
	}

	serviceAsBytes, errServiceAsBytes := base64.URLEncoding.DecodeString(
		tokenPayloadAsBase64,
	)
	if errServiceAsBytes != nil {
		return nil, errServiceAsBytes
	}
	serviceReturned := string(serviceAsBytes)

	return &serviceReturned, nil
}

func setSession(
	cacheAddress string,
	serverName string,
	tokenPayload *jwtx.TokenPayload,
	expirationInSeconds int64,
) (
	bool,
	error,
) {
	if tokenPayload == nil {
		return false, errTokenPayloadIsNil
	}

	tokenPayloadBytes, errTokenPayloadBytes := json.Marshal(*tokenPayload)
	if errTokenPayloadBytes != nil {
		return false, errTokenPayloadBytes
	}
	tokenPayloadAsStr := string(tokenPayloadBytes)

	setID := getCacheSetID(serverName, sessionTokens, *tokenPayload.Token)
	instructions := []interface{}{
		setCache,
		setID,
		tokenPayloadAsStr,
		expCache,
		expirationInSeconds,
	}

	return execAndReturnBool(cacheAddress, &instructions)
}

func CreateSession(
	cacheAddress string,
	serverName string,
	params *jwtx.CreateJWTParams,
) error {
	tokenPayload, errTokenPayload := jwtx.CreateJWT(params, nil)
	if errTokenPayload != nil {
		return errTokenPayload
	}

	sessionWasSet, errSetSession := setSession(
		cacheAddress,
		serverName,
		tokenPayload,
		params.Lifetime,
	)
	if errSetSession != nil {
		return errSetSession
	}

	if sessionWasSet {
		return nil
	}

	return errSessionWasNotStored
}

func VerifySession(
	cacheAddress string,
	serverName string,
	token string,
	audTarget string,
) (
	bool,
	error,
) {
	windowIsValid, errValidateWindow := jwtx.ValidateTokenByWindowAndAud(
		&token,
		audTarget,
		nil,
	)
	if !windowIsValid {
		return false, errValidateWindow
	}

	setID := getCacheSetID(serverName, sessionTokens, token)
	instructions := []interface{}{getCache, setID}
	tokenPayloadStr, errTokenPayloadStr := execAndParseTokenPayloadStr(
		cacheAddress,
		&instructions,
	)
	if errTokenPayloadStr != nil {
		return false, errTokenPayloadStr
	}
	if len(*tokenPayloadStr) == 0 {
		return false, errSessionDoesNotExist
	}

	var tokenPayload jwtx.TokenPayload
	errTokenPayload := json.Unmarshal([]byte(*tokenPayloadStr), &tokenPayload)

	return jwtx.ValidateJWT(&tokenPayload, errTokenPayload)
}
