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
	applicationJSON = "application/json"
	colonDelimiter  = ":"
	expCache        = "EX"
	getCache        = "GET"
	okCache         = "OK"
	sessionTokens   = "session_tokens"
	setCache        = "SET"
)

var (
	errTokenPayloadIsNil      = errors.New("token payload is nil")
	errInstructionsAreNil     = errors.New("instructions are nil")
	errSessionWasNotStored    = errors.New("session was not stored")
	errSessionDoesNotExist    = errors.New("session does not exist")
	errNilEntry               = errors.New("nil entry was provided")
	errRequestFailedToResolve = errors.New("request failed to resolve instructions")
)

func getCacheSetID(categories ...string) string {
	return strings.Join(categories, colonDelimiter)
}

func execInstructionsAndParseString(
	cacheAddress string,
	instructions *[]interface{},
) (
	*string,
	error,
) {
	if instructions == nil {
		return nil, errNilEntry
	}

	bodyBytes := new(bytes.Buffer)
	errJson := json.NewEncoder(bodyBytes).Encode(*instructions)
	if errJson != nil {
		return nil, errJson
	}

	resp, errResp := http.Post(cacheAddress, applicationJSON, bodyBytes)
	if errResp != nil {
		return nil, errResp
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errRequestFailedToResolve
	}

	var respBodyAsBase64 string
	errJSONResponse := json.NewDecoder(resp.Body).Decode(&respBodyAsBase64)
	if errJSONResponse != nil {
		return nil, errJSONResponse
	}

	return &respBodyAsBase64, errJSONResponse
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

	resp, errResp := http.Post(cacheAddress, applicationJSON, bodyBytes)
	if errResp != nil {
		return nil, errResp
	}
	defer resp.Body.Close()

	var tokenPayloadAsBase64 string
	errJSONResponse := json.NewDecoder(resp.Body).Decode(&tokenPayloadAsBase64)
	if errJSONResponse != nil {

		return nil, errJSONResponse
	}

	tokenPayloadAsBytes, errTokenPayloadAsBytes := base64.URLEncoding.DecodeString(
		tokenPayloadAsBase64,
	)
	if errTokenPayloadAsBytes != nil {
		return nil, errTokenPayloadAsBytes
	}
	serviceReturned := string(tokenPayloadAsBytes)

	return &serviceReturned, nil
}

func setSession(
	cacheAddress string,
	identifier string,
	tokenPayload *jwtx.TokenPayload,
	lifetimeInSeconds int64,
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

	setID := getCacheSetID(identifier, sessionTokens, *tokenPayload.Token)
	instructions := []interface{}{
		setCache,
		setID,
		tokenPayloadAsStr,
		expCache,
		lifetimeInSeconds,
	}

	respStr, errRespStr := execInstructionsAndParseString(cacheAddress, &instructions)
	if errRespStr != nil {
		return false, errRespStr
	}
	if *respStr == okCache {
		return true, nil
	}

	return false, errRequestFailedToResolve
}

func CreateSession(
	cacheAddress string,
	identifier string,
	params *jwtx.CreateJWTParams,
) error {
	tokenPayload, errTokenPayload := jwtx.CreateJWT(params, nil)
	if errTokenPayload != nil {
		return errTokenPayload
	}

	sessionWasSet, errSetSession := setSession(
		cacheAddress,
		identifier,
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
	identifier string,
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

	setID := getCacheSetID(identifier, sessionTokens, token)
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
