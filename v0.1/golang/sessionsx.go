package sessionslx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	jwtx "github.com/herebythere/jwtx/v0.1/golang"
)

const (
	applicationJson = "application/json"
	hset            = "HSET"
	hget            = "HGET"

	unableToWriteToCache = "unable to write jwt to cache"
	availableTokens      = "available_tokens"
	colonDelimiter       = ":"
)

var (
	localCacheAddress = os.Getenv("LOCAL_CACHE_ADDRESS")
	sessionCookieName = os.Getenv("SESSION_COOKIE_LABEL")

	errSuccessfulWrite         = errors.New("nil entry was provided")
	errNoCookie                = errors.New("no session cookie found")
	errTokenPayloadIsNil       = errors.New("token payload is nil")
	errInstructionsAreNil      = errors.New("instructions are nil")
	errSessionWasNotStored     = errors.New("session was not stored")
	errSessionDoesNotExist     = errors.New("session does not exist")
	errTokenIsExpired          = errors.New("token is expired")
	errTokenIssuedBeforeNow    = errors.New("token is issued before now")
	errTokenUsedBeforeExpected = errors.New("token was used before expected time")
	errAudChunkNotFound        = errors.New("audience chunk not found in token")
	errNilTokenDetails         = errors.New("nil token details")
)

// create session
func getCacheSetID(categories ...string) string {
	return strings.Join(categories, colonDelimiter)
}

func postJSONRequest(
	instructions []interface{},
) (
	*http.Response,
	error,
) {
	if instructions == nil {
		return nil, errInstructionsAreNil
	}

	instructionsAsJSON, errInstructionsAsJSON := json.Marshal(instructions)
	if errInstructionsAsJSON != nil {
		return nil, errInstructionsAsJSON
	}

	requestBody := bytes.NewBuffer(instructionsAsJSON)

	return http.Post(localCacheAddress, applicationJson, requestBody)
}

func parseCachedString(resp *http.Response) (*string, error) {
	var serviceAsBase64 string
	errJSONResponse := json.NewDecoder(resp.Body).Decode(&serviceAsBase64)
	if errJSONResponse != nil {

		return nil, errJSONResponse
	}

	serviceAsBytes, errServiceAsBytes := base64.URLEncoding.DecodeString(
		serviceAsBase64,
	)
	if errServiceAsBytes != nil {

		return nil, errServiceAsBytes
	}

	serviceReturned := string(serviceAsBytes)
	return &serviceReturned, nil
}

func setSession(serverName string, tokenPayload *jwtx.TokenPayload) (bool, error) {
	if tokenPayload == nil {
		return false, errTokenPayloadIsNil
	}
	setID := getCacheSetID(serverName, availableTokens)

	// marshal into json string
	tokenPayloadBytes, errTokenPayloadBytes := json.Marshal(*tokenPayload)
	if errTokenPayloadBytes != nil {
		return false, errTokenPayloadBytes
	}

	tokenPayloadJSONStr := string(tokenPayloadBytes)
	instructions := []interface{}{hset, setID, tokenPayload.Token, tokenPayloadJSONStr}

	// HSET does not fail
	resp, errResponse := postJSONRequest(instructions)
	if errResponse != nil {
		return false, errResponse
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, nil
}

func CreateSession(
	serverName string,
	params *jwtx.CreateJWTParams,
	err error,
) error {
	if err != nil {
		return err
	}

	tokenPayload, errTokenPayload := jwtx.CreateJWT(params, err)
	if errTokenPayload != nil {
		return errTokenPayload
	}

	sessionWasSet, errSetSession := setSession(serverName, tokenPayload)
	if errSetSession != nil {
		return errSetSession
	}

	if sessionWasSet {
		return nil
	}

	return errSessionWasNotStored
}

func findAudChunk(aud *[]string, audTarget string) bool {
	for _, audChunk := range *aud {
		if audChunk == audTarget {
			return true
		}
	}

	return false
}

func validateTokenWindowAndAud(token *string, audTarget string, err error) (bool, error) {
	tokenDetails, errTokenDetails := jwtx.RetrieveTokenDetails(token, err)
	if errTokenDetails != nil {
		return false, errTokenDetails
	}
	if tokenDetails == nil {
		return false, errNilTokenDetails
	}

	// check if role exists
	audChunkFound := findAudChunk(&tokenDetails.Claims.Aud, audTarget)
	if !audChunkFound {
		return false, errAudChunkNotFound
	}

	currentTime := time.Now().Unix()
	if tokenDetails.Claims.Iat > currentTime {
		return false, errTokenIssuedBeforeNow
	}

	if tokenDetails.Claims.Nbf != nil && *tokenDetails.Claims.Nbf > currentTime {

		return false, errTokenUsedBeforeExpected
	}

	lifetime := tokenDetails.Claims.Exp - currentTime

	if lifetime > 0 {

		return true, nil
	}

	return false, errTokenIsExpired
}

func VerifySession(serverName string, token string, audTarget string) (bool, error) {
	setID := getCacheSetID(serverName, availableTokens)
	instructions := []interface{}{hget, setID, token}
	resp, errResponse := postJSONRequest(instructions)
	if errResponse != nil {
		return false, errResponse
	}
	defer resp.Body.Close()

	decodedTokenPayload, errDecodedTokenPayload := parseCachedString(resp)
	if errDecodedTokenPayload != nil {
		return false, errDecodedTokenPayload
	}
	if len(*decodedTokenPayload) == 0 {
		return false, errSessionDoesNotExist
	}

	var tokenPayload jwtx.TokenPayload
	errTokenPayload := json.Unmarshal([]byte(*decodedTokenPayload), &tokenPayload)

	windowIsValid, errValidateWindow := jwtx.ValidateTokenByWindowAndAud(
		&token,
		audTarget,
		errTokenPayload,
	)
	if !windowIsValid {
		return false, errValidateWindow
	}

	return jwtx.ValidateJWT(&tokenPayload, errValidateWindow)
}
