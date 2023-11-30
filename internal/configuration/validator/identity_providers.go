package validator

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ory/fosite"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/utils"
)

// ValidateIdentityProviders validates and updates the IdentityProviders configuration.
func ValidateIdentityProviders(config *schema.IdentityProviders, validator *schema.StructValidator) {
	validateOIDC(config.OIDC, validator)
}

func validateOIDC(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	if config == nil {
		return
	}

	setOIDCDefaults(config)

	validateOIDCIssuer(config, validator)
	validateOIDCAuthorizationPolicies(config, validator)
	validateOIDCLifespans(config, validator)

	sort.Sort(oidc.SortedSigningAlgs(config.Discovery.ResponseObjectSigningAlgs))

	switch {
	case config.MinimumParameterEntropy == -1:
		validator.PushWarning(fmt.Errorf(errFmtOIDCProviderInsecureDisabledParameterEntropy))
	case config.MinimumParameterEntropy <= 0:
		config.MinimumParameterEntropy = fosite.MinParameterEntropy
	case config.MinimumParameterEntropy < fosite.MinParameterEntropy:
		validator.PushWarning(fmt.Errorf(errFmtOIDCProviderInsecureParameterEntropyUnsafe, fosite.MinParameterEntropy, config.MinimumParameterEntropy))
	}

	switch config.EnforcePKCE {
	case "always", "never", "public_clients_only":
		break
	default:
		validator.Push(fmt.Errorf(errFmtOIDCProviderEnforcePKCEInvalidValue, config.EnforcePKCE))
	}

	validateOIDCOptionsCORS(config, validator)

	if len(config.Clients) == 0 {
		validator.Push(fmt.Errorf(errFmtOIDCProviderNoClientsConfigured))
	} else {
		validateOIDCClients(config, validator)
	}
}

func validateOIDCAuthorizationPolicies(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	config.Discovery.AuthorizationPolicies = []string{policyOneFactor, policyTwoFactor}

	for name, policy := range config.AuthorizationPolicies {
		add := true

		switch name {
		case "":
			validator.Push(fmt.Errorf(errFmtOIDCPolicyInvalidName))

			add = false
		case policyOneFactor, policyTwoFactor, policyDeny:
			validator.Push(fmt.Errorf(errFmtOIDCPolicyInvalidNameStandard, name, "name", strJoinAnd([]string{policyOneFactor, policyTwoFactor, policyDeny}), name))

			add = false
		}

		switch policy.DefaultPolicy {
		case "":
			policy.DefaultPolicy = schema.DefaultOpenIDConnectPolicyConfiguration.DefaultPolicy
		case policyOneFactor, policyTwoFactor, policyDeny:
			break
		default:
			validator.Push(fmt.Errorf(errFmtOIDCPolicyInvalidDefaultPolicy, name, strJoinAnd([]string{policyOneFactor, policyTwoFactor, policyDeny}), policy.DefaultPolicy))
		}

		if len(policy.Rules) == 0 {
			validator.Push(fmt.Errorf(errFmtOIDCPolicyMissingOption, name, "rules"))
		}

		for i, rule := range policy.Rules {
			switch rule.Policy {
			case "":
				policy.Rules[i].Policy = schema.DefaultOpenIDConnectPolicyConfiguration.DefaultPolicy
			case policyOneFactor, policyTwoFactor, policyDeny:
				break
			default:
				validator.Push(fmt.Errorf(errFmtOIDCPolicyRuleInvalidPolicy, name, i+1, strJoinAnd([]string{policyOneFactor, policyTwoFactor, policyDeny}), rule.Policy))
			}

			if len(rule.Subjects) == 0 {
				validator.Push(fmt.Errorf(errFmtOIDCPolicyRuleMissingOption, name, i+1, "subject"))
			}
		}

		config.AuthorizationPolicies[name] = policy

		if add {
			config.Discovery.AuthorizationPolicies = append(config.Discovery.AuthorizationPolicies, name)
		}
	}
}

func validateOIDCLifespans(config *schema.IdentityProvidersOpenIDConnect, _ *schema.StructValidator) {
	for name := range config.Lifespans.Custom {
		config.Discovery.Lifespans = append(config.Discovery.Lifespans, name)
	}
}

func validateOIDCIssuer(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	switch {
	case config.IssuerPrivateKey != nil:
		validateOIDCIssuerPrivateKey(config)

		fallthrough
	case len(config.IssuerPrivateKeys) != 0:
		validateOIDCIssuerPrivateKeys(config, validator)
	default:
		validator.Push(fmt.Errorf(errFmtOIDCProviderNoPrivateKey))
	}
}

func validateOIDCIssuerPrivateKey(config *schema.IdentityProvidersOpenIDConnect) {
	config.IssuerPrivateKeys = append([]schema.JWK{{
		Algorithm:        oidc.SigningAlgRSAUsingSHA256,
		Use:              oidc.KeyUseSignature,
		Key:              config.IssuerPrivateKey,
		CertificateChain: config.IssuerCertificateChain,
	}}, config.IssuerPrivateKeys...)
}

func validateOIDCIssuerPrivateKeys(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	var (
		props *JWKProperties
		err   error
	)

	config.Discovery.ResponseObjectSigningKeyIDs = make([]string, len(config.IssuerPrivateKeys))
	config.Discovery.DefaultKeyIDs = map[string]string{}

	for i := 0; i < len(config.IssuerPrivateKeys); i++ {
		if key, ok := config.IssuerPrivateKeys[i].Key.(*rsa.PrivateKey); ok && key.PublicKey.N == nil {
			validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysInvalid, i+1))

			continue
		}

		switch n := len(config.IssuerPrivateKeys[i].KeyID); {
		case n == 0:
			if config.IssuerPrivateKeys[i].KeyID, err = jwkCalculateThumbprint(config.IssuerPrivateKeys[i].Key); err != nil {
				validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysCalcThumbprint, i+1, err))

				continue
			}
		case n > 100:
			validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysKeyIDLength, i+1, config.IssuerPrivateKeys[i].KeyID))
		}

		if config.IssuerPrivateKeys[i].KeyID != "" && utils.IsStringInSlice(config.IssuerPrivateKeys[i].KeyID, config.Discovery.ResponseObjectSigningKeyIDs) {
			validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysAttributeNotUnique, i+1, config.IssuerPrivateKeys[i].KeyID, attrOIDCKeyID))
		}

		config.Discovery.ResponseObjectSigningKeyIDs[i] = config.IssuerPrivateKeys[i].KeyID

		if !reOpenIDConnectKID.MatchString(config.IssuerPrivateKeys[i].KeyID) {
			validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysKeyIDNotValid, i+1, config.IssuerPrivateKeys[i].KeyID))
		}

		if props, err = schemaJWKGetProperties(config.IssuerPrivateKeys[i]); err != nil {
			validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysProperties, i+1, config.IssuerPrivateKeys[i].KeyID, err))

			continue
		}

		validateOIDCIssuerPrivateKeysUseAlg(i, props, config, validator)
		validateOIDCIssuerPrivateKeyPair(i, config, validator)
	}

	if len(config.Discovery.ResponseObjectSigningAlgs) != 0 && !utils.IsStringInSlice(oidc.SigningAlgRSAUsingSHA256, config.Discovery.ResponseObjectSigningAlgs) {
		validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysNoRS256, oidc.SigningAlgRSAUsingSHA256, strJoinAnd(config.Discovery.ResponseObjectSigningAlgs)))
	}
}

func validateOIDCIssuerPrivateKeysUseAlg(i int, props *JWKProperties, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	switch config.IssuerPrivateKeys[i].Use {
	case "":
		config.IssuerPrivateKeys[i].Use = props.Use
	case oidc.KeyUseSignature:
		break
	default:
		validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysInvalidOptionOneOf, i+1, config.IssuerPrivateKeys[i].KeyID, attrOIDCKeyUse, strJoinOr([]string{oidc.KeyUseSignature}), config.IssuerPrivateKeys[i].Use))
	}

	switch {
	case config.IssuerPrivateKeys[i].Algorithm == "":
		config.IssuerPrivateKeys[i].Algorithm = props.Algorithm

		fallthrough
	case utils.IsStringInSlice(config.IssuerPrivateKeys[i].Algorithm, validOIDCIssuerJWKSigningAlgs):
		if config.IssuerPrivateKeys[i].KeyID != "" && config.IssuerPrivateKeys[i].Algorithm != "" {
			if _, ok := config.Discovery.DefaultKeyIDs[config.IssuerPrivateKeys[i].Algorithm]; !ok {
				config.Discovery.DefaultKeyIDs[config.IssuerPrivateKeys[i].Algorithm] = config.IssuerPrivateKeys[i].KeyID
			}
		}
	default:
		validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysInvalidOptionOneOf, i+1, config.IssuerPrivateKeys[i].KeyID, attrOIDCAlgorithm, strJoinOr(validOIDCIssuerJWKSigningAlgs), config.IssuerPrivateKeys[i].Algorithm))
	}

	if config.IssuerPrivateKeys[i].Algorithm != "" {
		if !utils.IsStringInSlice(config.IssuerPrivateKeys[i].Algorithm, config.Discovery.ResponseObjectSigningAlgs) {
			config.Discovery.ResponseObjectSigningAlgs = append(config.Discovery.ResponseObjectSigningAlgs, config.IssuerPrivateKeys[i].Algorithm)
		}
	}
}

func validateOIDCIssuerPrivateKeyPair(i int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	var (
		checkEqualKey bool
		err           error
	)

	switch key := config.IssuerPrivateKeys[i].Key.(type) {
	case *rsa.PrivateKey:
		checkEqualKey = true

		if key.Size() < 256 {
			checkEqualKey = false

			validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysRSAKeyLessThan2048Bits, i+1, config.IssuerPrivateKeys[i].KeyID, key.Size()*8))
		}
	case *ecdsa.PrivateKey:
		checkEqualKey = true
	default:
		validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysKeyNotRSAOrECDSA, i+1, config.IssuerPrivateKeys[i].KeyID, key))
	}

	if config.IssuerPrivateKeys[i].CertificateChain.HasCertificates() {
		if checkEqualKey && !config.IssuerPrivateKeys[i].CertificateChain.EqualKey(config.IssuerPrivateKeys[i].Key) {
			validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysKeyCertificateMismatch, i+1, config.IssuerPrivateKeys[i].KeyID))
		}

		if err = config.IssuerPrivateKeys[i].CertificateChain.Validate(); err != nil {
			validator.Push(fmt.Errorf(errFmtOIDCProviderPrivateKeysCertificateChainInvalid, i+1, config.IssuerPrivateKeys[i].KeyID, err))
		}
	}
}

func setOIDCDefaults(config *schema.IdentityProvidersOpenIDConnect) {
	if config.Lifespans.AccessToken == durationZero {
		config.Lifespans.AccessToken = schema.DefaultOpenIDConnectConfiguration.Lifespans.AccessToken
	}

	if config.Lifespans.AuthorizeCode == durationZero {
		config.Lifespans.AuthorizeCode = schema.DefaultOpenIDConnectConfiguration.Lifespans.AuthorizeCode
	}

	if config.Lifespans.IDToken == durationZero {
		config.Lifespans.IDToken = schema.DefaultOpenIDConnectConfiguration.Lifespans.IDToken
	}

	if config.Lifespans.RefreshToken == durationZero {
		config.Lifespans.RefreshToken = schema.DefaultOpenIDConnectConfiguration.Lifespans.RefreshToken
	}

	if config.EnforcePKCE == "" {
		config.EnforcePKCE = schema.DefaultOpenIDConnectConfiguration.EnforcePKCE
	}
}

func validateOIDCOptionsCORS(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	validateOIDCOptionsCORSAllowedOrigins(config, validator)

	if config.CORS.AllowedOriginsFromClientRedirectURIs {
		validateOIDCOptionsCORSAllowedOriginsFromClientRedirectURIs(config)
	}

	validateOIDCOptionsCORSEndpoints(config, validator)
}

func validateOIDCOptionsCORSAllowedOrigins(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	for _, origin := range config.CORS.AllowedOrigins {
		if origin.String() == "*" {
			if len(config.CORS.AllowedOrigins) != 1 {
				validator.Push(fmt.Errorf(errFmtOIDCCORSInvalidOriginWildcard))
			}

			if config.CORS.AllowedOriginsFromClientRedirectURIs {
				validator.Push(fmt.Errorf(errFmtOIDCCORSInvalidOriginWildcardWithClients))
			}

			continue
		}

		if origin.Path != "" {
			validator.Push(fmt.Errorf(errFmtOIDCCORSInvalidOrigin, origin.String(), "path"))
		}

		if origin.RawQuery != "" {
			validator.Push(fmt.Errorf(errFmtOIDCCORSInvalidOrigin, origin.String(), "query string"))
		}
	}
}

func validateOIDCOptionsCORSAllowedOriginsFromClientRedirectURIs(config *schema.IdentityProvidersOpenIDConnect) {
	for _, client := range config.Clients {
		for _, redirectURI := range client.RedirectURIs {
			uri, err := url.ParseRequestURI(redirectURI)
			if err != nil || (uri.Scheme != schemeHTTP && uri.Scheme != schemeHTTPS) || uri.Hostname() == "localhost" {
				continue
			}

			origin := utils.OriginFromURL(uri)

			if !utils.IsURLInSlice(*origin, config.CORS.AllowedOrigins) {
				config.CORS.AllowedOrigins = append(config.CORS.AllowedOrigins, *origin)
			}
		}
	}
}

func validateOIDCOptionsCORSEndpoints(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	for _, endpoint := range config.CORS.Endpoints {
		if !utils.IsStringInSlice(endpoint, validOIDCCORSEndpoints) {
			validator.Push(fmt.Errorf(errFmtOIDCCORSInvalidEndpoint, endpoint, strJoinOr(validOIDCCORSEndpoints)))
		}
	}
}

func validateOIDCClients(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	var (
		errDeprecated bool

		clientIDs, duplicateClientIDs, blankClientIDs []string
	)

	errDeprecatedFunc := func() { errDeprecated = true }

	for c, client := range config.Clients {
		if client.ID == "" {
			blankClientIDs = append(blankClientIDs, "#"+strconv.Itoa(c+1))
		} else {
			if client.Description == "" {
				config.Clients[c].Description = client.ID
			}

			if id := strings.ToLower(client.ID); utils.IsStringInSlice(id, clientIDs) {
				if !utils.IsStringInSlice(id, duplicateClientIDs) {
					duplicateClientIDs = append(duplicateClientIDs, id)
				}
			} else {
				clientIDs = append(clientIDs, id)
			}
		}

		validateOIDCClient(c, config, validator, errDeprecatedFunc)
	}

	if errDeprecated {
		validator.PushWarning(fmt.Errorf(errFmtOIDCClientsDeprecated))
	}

	if len(blankClientIDs) != 0 {
		validator.Push(fmt.Errorf(errFmtOIDCClientsWithEmptyID, buildJoinedString(", ", "or", "", blankClientIDs)))
	}

	if len(duplicateClientIDs) != 0 {
		validator.Push(fmt.Errorf(errFmtOIDCClientsDuplicateID, strJoinOr(duplicateClientIDs)))
	}
}

func validateOIDCClient(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator, errDeprecatedFunc func()) {
	switch {
	case config.Clients[c].AuthorizationPolicy == "":
		config.Clients[c].AuthorizationPolicy = schema.DefaultOpenIDConnectClientConfiguration.AuthorizationPolicy
	case utils.IsStringInSlice(config.Clients[c].AuthorizationPolicy, config.Discovery.AuthorizationPolicies):
		break
	default:
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue, config.Clients[c].ID, "authorization_policy", strJoinOr(config.Discovery.AuthorizationPolicies), config.Clients[c].AuthorizationPolicy))
	}

	switch {
	case config.Clients[c].Lifespan == "", utils.IsStringInSlice(config.Clients[c].Lifespan, config.Discovery.Lifespans):
		break
	default:
		if len(config.Discovery.Lifespans) == 0 {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidLifespan, config.Clients[c].ID, config.Clients[c].Lifespan))
		} else {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue, config.Clients[c].ID, "lifespan", strJoinOr(config.Discovery.Lifespans), config.Clients[c].Lifespan))
		}
	}

	switch config.Clients[c].PKCEChallengeMethod {
	case "", oidc.PKCEChallengeMethodPlain, oidc.PKCEChallengeMethodSHA256:
		break
	default:
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue, config.Clients[c].ID, attrOIDCPKCEChallengeMethod, strJoinOr([]string{oidc.PKCEChallengeMethodPlain, oidc.PKCEChallengeMethodSHA256}), config.Clients[c].PKCEChallengeMethod))
	}

	switch config.Clients[c].RequestedAudienceMode {
	case "":
		config.Clients[c].RequestedAudienceMode = schema.DefaultOpenIDConnectClientConfiguration.RequestedAudienceMode
	case oidc.ClientRequestedAudienceModeExplicit.String(), oidc.ClientRequestedAudienceModeImplicit.String():
		break
	default:
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue, config.Clients[c].ID, attrOIDCRequestedAudienceMode, strJoinOr([]string{oidc.ClientRequestedAudienceModeExplicit.String(), oidc.ClientRequestedAudienceModeImplicit.String()}), config.Clients[c].RequestedAudienceMode))
	}

	validateOIDCClientConsentMode(c, config, validator)

	validateOIDCClientScopes(c, config, validator, errDeprecatedFunc)
	validateOIDCClientResponseTypes(c, config, validator, errDeprecatedFunc)
	validateOIDCClientResponseModes(c, config, validator, errDeprecatedFunc)
	validateOIDCClientGrantTypes(c, config, validator, errDeprecatedFunc)
	validateOIDCClientRedirectURIs(c, config, validator, errDeprecatedFunc)

	validateOIDDClientSigningAlgs(c, config, validator)

	validateOIDCClientSectorIdentifier(c, config, validator)

	validateOIDCClientPublicKeys(c, config, validator)
	validateOIDCClientTokenEndpointAuth(c, config, validator)
}

func validateOIDCClientPublicKeys(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	switch {
	case config.Clients[c].PublicKeys.URI != nil && len(config.Clients[c].PublicKeys.Values) != 0:
		validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysBothURIAndValuesConfigured, config.Clients[c].ID))
	case config.Clients[c].PublicKeys.URI != nil:
		if config.Clients[c].PublicKeys.URI.Scheme != schemeHTTPS {
			validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysURIInvalidScheme, config.Clients[c].ID, config.Clients[c].PublicKeys.URI.Scheme))
		}
	case len(config.Clients[c].PublicKeys.Values) != 0:
		validateOIDCClientJSONWebKeysList(c, config, validator)
	}
}

func validateOIDCClientJSONWebKeysList(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	var (
		props *JWKProperties
		err   error
	)

	for i := 0; i < len(config.Clients[c].PublicKeys.Values); i++ {
		if config.Clients[c].PublicKeys.Values[i].KeyID == "" {
			validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysInvalidOptionMissingOneOf, config.Clients[c].ID, i+1, attrOIDCKeyID))
		}

		if props, err = schemaJWKGetProperties(config.Clients[c].PublicKeys.Values[i]); err != nil {
			validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysProperties, config.Clients[c].ID, i+1, config.Clients[c].PublicKeys.Values[i].KeyID, err))

			continue
		}

		validateOIDCClientJSONWebKeysListKeyUseAlg(c, i, props, config, validator)

		var checkEqualKey bool

		switch key := config.Clients[c].PublicKeys.Values[i].Key.(type) {
		case nil:
			validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysInvalidOptionMissingOneOf, config.Clients[c].ID, i+1, attrOIDCKey))
		case *rsa.PublicKey:
			checkEqualKey = true

			if key.N == nil {
				checkEqualKey = false

				validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysKeyMalformed, config.Clients[c].ID, i+1))
			} else if key.Size() < 256 {
				checkEqualKey = false

				validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysRSAKeyLessThan2048Bits, config.Clients[c].ID, i+1, config.Clients[c].PublicKeys.Values[i].KeyID, key.Size()*8))
			}
		case *ecdsa.PublicKey:
			checkEqualKey = true
		default:
			validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysKeyNotRSAOrECDSA, config.Clients[c].ID, i+1, config.Clients[c].PublicKeys.Values[i].KeyID, key))
		}

		if config.Clients[c].PublicKeys.Values[i].CertificateChain.HasCertificates() {
			if checkEqualKey && !config.Clients[c].PublicKeys.Values[i].CertificateChain.EqualKey(config.Clients[c].PublicKeys.Values[i].Key) {
				validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysCertificateChainKeyMismatch, config.Clients[c].ID, i+1, config.Clients[c].PublicKeys.Values[i].KeyID))
			}

			if err = config.Clients[c].PublicKeys.Values[i].CertificateChain.Validate(); err != nil {
				validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysCertificateChainInvalid, config.Clients[c].ID, i+1, config.Clients[c].PublicKeys.Values[i].KeyID, err))
			}
		}
	}

	if config.Clients[c].RequestObjectSigningAlg != "" && !utils.IsStringInSlice(config.Clients[c].RequestObjectSigningAlg, config.Clients[c].Discovery.RequestObjectSigningAlgs) {
		validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysROSAMissingAlgorithm, config.Clients[c].ID, strJoinOr(config.Clients[c].Discovery.RequestObjectSigningAlgs)))
	}
}

func validateOIDCClientJSONWebKeysListKeyUseAlg(c, i int, props *JWKProperties, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	switch config.Clients[c].PublicKeys.Values[i].Use {
	case "":
		config.Clients[c].PublicKeys.Values[i].Use = props.Use
	case oidc.KeyUseSignature:
		break
	default:
		validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysInvalidOptionOneOf, config.Clients[c].ID, i+1, config.Clients[c].PublicKeys.Values[i].KeyID, attrOIDCKeyUse, strJoinOr([]string{oidc.KeyUseSignature}), config.Clients[c].PublicKeys.Values[i].Use))
	}

	switch {
	case config.Clients[c].PublicKeys.Values[i].Algorithm == "":
		config.Clients[c].PublicKeys.Values[i].Algorithm = props.Algorithm
	case utils.IsStringInSlice(config.Clients[c].PublicKeys.Values[i].Algorithm, validOIDCIssuerJWKSigningAlgs):
		break
	default:
		validator.Push(fmt.Errorf(errFmtOIDCClientPublicKeysInvalidOptionOneOf, config.Clients[c].ID, i+1, config.Clients[c].PublicKeys.Values[i].KeyID, attrOIDCAlgorithm, strJoinOr(validOIDCIssuerJWKSigningAlgs), config.Clients[c].PublicKeys.Values[i].Algorithm))
	}

	if config.Clients[c].PublicKeys.Values[i].Algorithm != "" {
		if !utils.IsStringInSlice(config.Clients[c].PublicKeys.Values[i].Algorithm, config.Discovery.RequestObjectSigningAlgs) {
			config.Discovery.RequestObjectSigningAlgs = append(config.Discovery.RequestObjectSigningAlgs, config.Clients[c].PublicKeys.Values[i].Algorithm)
		}

		if !utils.IsStringInSlice(config.Clients[c].PublicKeys.Values[i].Algorithm, config.Clients[c].Discovery.RequestObjectSigningAlgs) {
			config.Clients[c].Discovery.RequestObjectSigningAlgs = append(config.Clients[c].Discovery.RequestObjectSigningAlgs, config.Clients[c].PublicKeys.Values[i].Algorithm)
		}
	}
}

func validateOIDCClientSectorIdentifier(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	if config.Clients[c].SectorIdentifier.String() != "" {
		if utils.IsURLHostComponent(config.Clients[c].SectorIdentifier) || utils.IsURLHostComponentWithPort(config.Clients[c].SectorIdentifier) {
			return
		}

		if config.Clients[c].SectorIdentifier.Scheme != "" {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSectorIdentifier, config.Clients[c].ID, config.Clients[c].SectorIdentifier.String(), config.Clients[c].SectorIdentifier.Host, "scheme", config.Clients[c].SectorIdentifier.Scheme))

			if config.Clients[c].SectorIdentifier.Path != "" {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSectorIdentifier, config.Clients[c].ID, config.Clients[c].SectorIdentifier.String(), config.Clients[c].SectorIdentifier.Host, "path", config.Clients[c].SectorIdentifier.Path))
			}

			if config.Clients[c].SectorIdentifier.RawQuery != "" {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSectorIdentifier, config.Clients[c].ID, config.Clients[c].SectorIdentifier.String(), config.Clients[c].SectorIdentifier.Host, "query", config.Clients[c].SectorIdentifier.RawQuery))
			}

			if config.Clients[c].SectorIdentifier.Fragment != "" {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSectorIdentifier, config.Clients[c].ID, config.Clients[c].SectorIdentifier.String(), config.Clients[c].SectorIdentifier.Host, "fragment", config.Clients[c].SectorIdentifier.Fragment))
			}

			if config.Clients[c].SectorIdentifier.User != nil {
				if config.Clients[c].SectorIdentifier.User.Username() != "" {
					validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSectorIdentifier, config.Clients[c].ID, config.Clients[c].SectorIdentifier.String(), config.Clients[c].SectorIdentifier.Host, "username", config.Clients[c].SectorIdentifier.User.Username()))
				}

				if _, set := config.Clients[c].SectorIdentifier.User.Password(); set {
					validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSectorIdentifierWithoutValue, config.Clients[c].ID, config.Clients[c].SectorIdentifier.String(), config.Clients[c].SectorIdentifier.Host, "password"))
				}
			}
		} else if config.Clients[c].SectorIdentifier.Host == "" {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSectorIdentifierHost, config.Clients[c].ID, config.Clients[c].SectorIdentifier.String()))
		}
	}
}

func validateOIDCClientConsentMode(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	switch {
	case utils.IsStringInSlice(config.Clients[c].ConsentMode, []string{"", auto}):
		if config.Clients[c].ConsentPreConfiguredDuration != nil {
			config.Clients[c].ConsentMode = oidc.ClientConsentModePreConfigured.String()
		} else {
			config.Clients[c].ConsentMode = oidc.ClientConsentModeExplicit.String()
		}
	case utils.IsStringInSlice(config.Clients[c].ConsentMode, validOIDCClientConsentModes):
		break
	default:
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidConsentMode, config.Clients[c].ID, strJoinOr(append(validOIDCClientConsentModes, auto)), config.Clients[c].ConsentMode))
	}

	if config.Clients[c].ConsentMode == oidc.ClientConsentModePreConfigured.String() && config.Clients[c].ConsentPreConfiguredDuration == nil {
		config.Clients[c].ConsentPreConfiguredDuration = schema.DefaultOpenIDConnectClientConfiguration.ConsentPreConfiguredDuration
	}
}

func validateOIDCClientScopes(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator, errDeprecatedFunc func()) {
	if len(config.Clients[c].Scopes) == 0 {
		config.Clients[c].Scopes = schema.DefaultOpenIDConnectClientConfiguration.Scopes
	}

	invalid, duplicates := validateList(config.Clients[c].Scopes, validOIDCClientScopes, true)

	if len(duplicates) != 0 {
		errDeprecatedFunc()

		validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidEntryDuplicates, config.Clients[c].ID, attrOIDCScopes, strJoinAnd(duplicates)))
	}

	if !config.Discovery.BearerAuthorization {
		if utils.IsStringInSlice(oidc.ScopeAutheliaAuthzBearer, config.Clients[c].Scopes) {
			config.Discovery.BearerAuthorization = true
		}
	}

	if utils.IsStringInSlice(oidc.GrantTypeClientCredentials, config.Clients[c].GrantTypes) {
		validateOIDCClientScopesClientCredentialsGrant(c, config, validator)
	} else {
		if !utils.IsStringInSlice(oidc.ScopeOpenID, config.Clients[c].Scopes) {
			config.Clients[c].Scopes = append([]string{oidc.ScopeOpenID}, config.Clients[c].Scopes...)
		}

		if len(invalid) != 0 {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidEntries, config.Clients[c].ID, attrOIDCScopes, strJoinOr(validOIDCClientScopes), strJoinAnd(invalid)))
		}
	}

	if utils.IsStringSliceContainsAny([]string{oidc.ScopeOfflineAccess, oidc.ScopeOffline}, config.Clients[c].Scopes) &&
		!utils.IsStringSliceContainsAny(validOIDCClientResponseTypesRefreshToken, config.Clients[c].ResponseTypes) {
		errDeprecatedFunc()

		validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidRefreshTokenOptionWithoutCodeResponseType,
			config.Clients[c].ID, attrOIDCScopes,
			strJoinOr([]string{oidc.ScopeOfflineAccess, oidc.ScopeOffline}),
			strJoinOr(validOIDCClientResponseTypesRefreshToken)),
		)
	}
}

func validateOIDCClientScopesClientCredentialsGrant(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	if len(config.Clients[c].GrantTypes) != 1 {
		return
	}

	invalid := validateListNotAllowed(config.Clients[c].Scopes, []string{oidc.ScopeOpenID, oidc.ScopeOffline, oidc.ScopeOfflineAccess})

	if len(invalid) > 0 {
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidEntriesClientCredentials, config.Clients[c].ID, strJoinAnd(config.Clients[c].Scopes), strJoinOr(invalid)))
	}
}

func validateOIDCClientResponseTypes(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator, errDeprecatedFunc func()) {
	if len(config.Clients[c].ResponseTypes) == 0 {
		config.Clients[c].ResponseTypes = schema.DefaultOpenIDConnectClientConfiguration.ResponseTypes
	}

	invalid, duplicates := validateList(config.Clients[c].ResponseTypes, validOIDCClientResponseTypes, true)

	if len(invalid) != 0 {
		validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidEntries, config.Clients[c].ID, attrOIDCResponseTypes, strJoinOr(validOIDCClientResponseTypes), strJoinAnd(invalid)))
	}

	if len(duplicates) != 0 {
		errDeprecatedFunc()

		validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidEntryDuplicates, config.Clients[c].ID, attrOIDCResponseTypes, strJoinAnd(duplicates)))
	}
}

func validateOIDCClientResponseModes(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator, errDeprecatedFunc func()) {
	if len(config.Clients[c].ResponseModes) == 0 {
		config.Clients[c].ResponseModes = schema.DefaultOpenIDConnectClientConfiguration.ResponseModes

		for _, responseType := range config.Clients[c].ResponseTypes {
			switch responseType {
			case oidc.ResponseTypeAuthorizationCodeFlow:
				if !utils.IsStringInSlice(oidc.ResponseModeQuery, config.Clients[c].ResponseModes) {
					config.Clients[c].ResponseModes = append(config.Clients[c].ResponseModes, oidc.ResponseModeQuery)
				}
			case oidc.ResponseTypeImplicitFlowIDToken, oidc.ResponseTypeImplicitFlowToken, oidc.ResponseTypeImplicitFlowBoth,
				oidc.ResponseTypeHybridFlowIDToken, oidc.ResponseTypeHybridFlowToken, oidc.ResponseTypeHybridFlowBoth:
				if !utils.IsStringInSlice(oidc.ResponseModeFragment, config.Clients[c].ResponseModes) {
					config.Clients[c].ResponseModes = append(config.Clients[c].ResponseModes, oidc.ResponseModeFragment)
				}
			}
		}
	}

	invalid, duplicates := validateList(config.Clients[c].ResponseModes, validOIDCClientResponseModes, true)

	if len(invalid) != 0 {
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidEntries, config.Clients[c].ID, attrOIDCResponseModes, strJoinOr(validOIDCClientResponseModes), strJoinAnd(invalid)))
	}

	if len(duplicates) != 0 {
		errDeprecatedFunc()

		validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidEntryDuplicates, config.Clients[c].ID, attrOIDCResponseModes, strJoinAnd(duplicates)))
	}
}

func validateOIDCClientGrantTypes(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator, errDeprecatedFunc func()) {
	if len(config.Clients[c].GrantTypes) == 0 {
		validateOIDCClientGrantTypesSetDefaults(c, config)
	}

	validateOIDCClientGrantTypesCheckRelated(c, config, validator, errDeprecatedFunc)

	invalid, duplicates := validateList(config.Clients[c].GrantTypes, validOIDCClientGrantTypes, true)

	if len(invalid) != 0 {
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidEntries, config.Clients[c].ID, attrOIDCGrantTypes, strJoinOr(validOIDCClientGrantTypes), strJoinAnd(invalid)))
	}

	if len(duplicates) != 0 {
		errDeprecatedFunc()

		validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidEntryDuplicates, config.Clients[c].ID, attrOIDCGrantTypes, strJoinAnd(duplicates)))
	}
}

func validateOIDCClientGrantTypesSetDefaults(c int, config *schema.IdentityProvidersOpenIDConnect) {
	for _, responseType := range config.Clients[c].ResponseTypes {
		switch responseType {
		case oidc.ResponseTypeAuthorizationCodeFlow:
			if !utils.IsStringInSlice(oidc.GrantTypeAuthorizationCode, config.Clients[c].GrantTypes) {
				config.Clients[c].GrantTypes = append(config.Clients[c].GrantTypes, oidc.GrantTypeAuthorizationCode)
			}
		case oidc.ResponseTypeImplicitFlowIDToken, oidc.ResponseTypeImplicitFlowToken, oidc.ResponseTypeImplicitFlowBoth:
			if !utils.IsStringInSlice(oidc.GrantTypeImplicit, config.Clients[c].GrantTypes) {
				config.Clients[c].GrantTypes = append(config.Clients[c].GrantTypes, oidc.GrantTypeImplicit)
			}
		case oidc.ResponseTypeHybridFlowIDToken, oidc.ResponseTypeHybridFlowToken, oidc.ResponseTypeHybridFlowBoth:
			if !utils.IsStringInSlice(oidc.GrantTypeAuthorizationCode, config.Clients[c].GrantTypes) {
				config.Clients[c].GrantTypes = append(config.Clients[c].GrantTypes, oidc.GrantTypeAuthorizationCode)
			}

			if !utils.IsStringInSlice(oidc.GrantTypeImplicit, config.Clients[c].GrantTypes) {
				config.Clients[c].GrantTypes = append(config.Clients[c].GrantTypes, oidc.GrantTypeImplicit)
			}
		}
	}
}

func validateOIDCClientGrantTypesCheckRelated(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator, errDeprecatedFunc func()) {
	for _, grantType := range config.Clients[c].GrantTypes {
		switch grantType {
		case oidc.GrantTypeAuthorizationCode:
			if !utils.IsStringInSlice(oidc.ResponseTypeAuthorizationCodeFlow, config.Clients[c].ResponseTypes) && !utils.IsStringSliceContainsAny(validOIDCClientResponseTypesHybridFlow, config.Clients[c].ResponseTypes) {
				errDeprecatedFunc()

				validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidGrantTypeMatch, config.Clients[c].ID, grantType, "for either the authorization code or hybrid flow", strJoinOr(append([]string{oidc.ResponseTypeAuthorizationCodeFlow}, validOIDCClientResponseTypesHybridFlow...)), strJoinAnd(config.Clients[c].ResponseTypes)))
			}
		case oidc.GrantTypeImplicit:
			if !utils.IsStringSliceContainsAny(validOIDCClientResponseTypesImplicitFlow, config.Clients[c].ResponseTypes) && !utils.IsStringSliceContainsAny(validOIDCClientResponseTypesHybridFlow, config.Clients[c].ResponseTypes) {
				errDeprecatedFunc()

				validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidGrantTypeMatch, config.Clients[c].ID, grantType, "for either the implicit or hybrid flow", strJoinOr(append(append([]string{}, validOIDCClientResponseTypesImplicitFlow...), validOIDCClientResponseTypesHybridFlow...)), strJoinAnd(config.Clients[c].ResponseTypes)))
			}
		case oidc.GrantTypeClientCredentials:
			if config.Clients[c].Public {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidGrantTypePublic, config.Clients[c].ID, oidc.GrantTypeClientCredentials))
			}
		case oidc.GrantTypeRefreshToken:
			if !utils.IsStringSliceContainsAny([]string{oidc.ScopeOfflineAccess, oidc.ScopeOffline}, config.Clients[c].Scopes) {
				errDeprecatedFunc()

				validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidGrantTypeRefresh, config.Clients[c].ID))
			}

			if !utils.IsStringSliceContainsAny(validOIDCClientResponseTypesRefreshToken, config.Clients[c].ResponseTypes) {
				errDeprecatedFunc()

				validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidRefreshTokenOptionWithoutCodeResponseType,
					config.Clients[c].ID, attrOIDCGrantTypes,
					strJoinOr([]string{oidc.GrantTypeRefreshToken}),
					strJoinOr(validOIDCClientResponseTypesRefreshToken)),
				)
			}
		}
	}
}

func validateOIDCClientRedirectURIs(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator, errDeprecatedFunc func()) {
	var (
		parsedRedirectURI *url.URL
		err               error
	)

	for _, redirectURI := range config.Clients[c].RedirectURIs {
		if redirectURI == oauth2InstalledApp {
			if config.Clients[c].Public {
				continue
			}

			validator.Push(fmt.Errorf(errFmtOIDCClientRedirectURIPublic, config.Clients[c].ID, oauth2InstalledApp))

			continue
		}

		if parsedRedirectURI, err = url.Parse(redirectURI); err != nil {
			validator.Push(fmt.Errorf(errFmtOIDCClientRedirectURICantBeParsed, config.Clients[c].ID, redirectURI, err))
			continue
		}

		if !parsedRedirectURI.IsAbs() || (!config.Clients[c].Public && parsedRedirectURI.Scheme == "") {
			validator.Push(fmt.Errorf(errFmtOIDCClientRedirectURIAbsolute, config.Clients[c].ID, redirectURI))
		}
	}

	_, duplicates := validateList(config.Clients[c].RedirectURIs, nil, true)

	if len(duplicates) != 0 {
		errDeprecatedFunc()

		validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidEntryDuplicates, config.Clients[c].ID, attrOIDCRedirectURIs, strJoinAnd(duplicates)))
	}
}

//nolint:gocyclo
func validateOIDCClientTokenEndpointAuth(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	implicit := len(config.Clients[c].ResponseTypes) != 0 && utils.IsStringSliceContainsAll(config.Clients[c].ResponseTypes, validOIDCClientResponseTypesImplicitFlow)

	switch {
	case config.Clients[c].TokenEndpointAuthMethod == "":
		break
	case !utils.IsStringInSlice(config.Clients[c].TokenEndpointAuthMethod, validOIDCClientTokenEndpointAuthMethods):
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
			config.Clients[c].ID, attrOIDCTokenAuthMethod, strJoinOr(validOIDCClientTokenEndpointAuthMethods), config.Clients[c].TokenEndpointAuthMethod))

		return
	case config.Clients[c].TokenEndpointAuthMethod == oidc.ClientAuthMethodNone && !config.Clients[c].Public && !implicit:
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidTokenEndpointAuthMethod,
			config.Clients[c].ID, strJoinOr(validOIDCClientTokenEndpointAuthMethodsConfidential), strJoinAnd(validOIDCClientResponseTypesImplicitFlow), config.Clients[c].TokenEndpointAuthMethod))
	case config.Clients[c].TokenEndpointAuthMethod != oidc.ClientAuthMethodNone && config.Clients[c].Public:
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidTokenEndpointAuthMethodPublic,
			config.Clients[c].ID, config.Clients[c].TokenEndpointAuthMethod))
	}

	secret := false

	switch config.Clients[c].TokenEndpointAuthMethod {
	case oidc.ClientAuthMethodClientSecretJWT:
		validateOIDCClientTokenEndpointAuthClientSecretJWT(c, config, validator)

		secret = true
	case "":
		if !config.Clients[c].Public {
			secret = true
		}
	case oidc.ClientAuthMethodClientSecretPost, oidc.ClientAuthMethodClientSecretBasic:
		secret = true
	case oidc.ClientAuthMethodPrivateKeyJWT:
		validateOIDCClientTokenEndpointAuthPublicKeyJWT(config.Clients[c], validator)
	}

	if secret {
		if config.Clients[c].Public {
			return
		}

		if config.Clients[c].Secret == nil {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSecret, config.Clients[c].ID))
		} else {
			switch {
			case config.Clients[c].Secret.IsPlainText() && config.Clients[c].TokenEndpointAuthMethod != oidc.ClientAuthMethodClientSecretJWT:
				validator.PushWarning(fmt.Errorf(errFmtOIDCClientInvalidSecretPlainText, config.Clients[c].ID))
			case !config.Clients[c].Secret.IsPlainText() && config.Clients[c].TokenEndpointAuthMethod == oidc.ClientAuthMethodClientSecretJWT:
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidSecretNotPlainText, config.Clients[c].ID))
			}
		}
	} else if config.Clients[c].Secret != nil {
		if config.Clients[c].Public {
			validator.Push(fmt.Errorf(errFmtOIDCClientPublicInvalidSecret, config.Clients[c].ID))
		} else {
			validator.Push(fmt.Errorf(errFmtOIDCClientPublicInvalidSecretClientAuthMethod, config.Clients[c].ID, config.Clients[c].TokenEndpointAuthMethod))
		}
	}
}

func validateOIDCClientTokenEndpointAuthClientSecretJWT(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	switch {
	case config.Clients[c].TokenEndpointAuthSigningAlg == "":
		config.Clients[c].TokenEndpointAuthSigningAlg = oidc.SigningAlgHMACUsingSHA256
	case !utils.IsStringInSlice(config.Clients[c].TokenEndpointAuthSigningAlg, validOIDCClientTokenEndpointAuthSigAlgsClientSecretJWT):
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidTokenEndpointAuthSigAlg, config.Clients[c].ID, strJoinOr(validOIDCClientTokenEndpointAuthSigAlgsClientSecretJWT), config.Clients[c].TokenEndpointAuthMethod))
	}
}

func validateOIDCClientTokenEndpointAuthPublicKeyJWT(config schema.IdentityProvidersOpenIDConnectClient, validator *schema.StructValidator) {
	switch {
	case config.TokenEndpointAuthSigningAlg == "":
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidTokenEndpointAuthSigAlgMissingPrivateKeyJWT, config.ID))
	case !utils.IsStringInSlice(config.TokenEndpointAuthSigningAlg, validOIDCIssuerJWKSigningAlgs):
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidTokenEndpointAuthSigAlg, config.ID, strJoinOr(validOIDCIssuerJWKSigningAlgs), config.TokenEndpointAuthMethod))
	}

	if config.PublicKeys.URI == nil {
		if len(config.PublicKeys.Values) == 0 {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidPublicKeysPrivateKeyJWT, config.ID))
		} else if len(config.Discovery.RequestObjectSigningAlgs) != 0 && !utils.IsStringInSlice(config.TokenEndpointAuthSigningAlg, config.Discovery.RequestObjectSigningAlgs) {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidTokenEndpointAuthSigAlgReg, config.ID, strJoinOr(config.Discovery.RequestObjectSigningAlgs), config.TokenEndpointAuthMethod))
		}
	}
}

func validateOIDDClientSigningAlgs(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	validateOIDDClientSigningAlgsJARM(c, config, validator)
	validateOIDDClientSigningAlgsIDToken(c, config, validator)
	validateOIDDClientSigningAlgsAccessToken(c, config, validator)
	validateOIDDClientSigningAlgsUserInfo(c, config, validator)
	validateOIDDClientSigningAlgsIntrospection(c, config, validator)
}

func validateOIDDClientSigningAlgsIDToken(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	config.Clients[c].IDTokenSignedResponseAlg, config.Clients[c].IDTokenSignedResponseKeyID = validateOIDCClientAlgKIDDefault(config, config.Clients[c].IDTokenSignedResponseAlg, config.Clients[c].IDTokenSignedResponseKeyID, schema.DefaultOpenIDConnectClientConfiguration.IDTokenSignedResponseAlg)

	switch config.Clients[c].IDTokenSignedResponseKeyID {
	case "":
		switch config.Clients[c].IDTokenSignedResponseAlg {
		case "", oidc.SigningAlgRSAUsingSHA256:
			break
		default:
			if !utils.IsStringInSlice(config.Clients[c].IDTokenSignedResponseAlg, config.Discovery.ResponseObjectSigningAlgs) {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
					config.Clients[c].ID, attrOIDCIDTokenSigAlg, strJoinOr(config.Discovery.ResponseObjectSigningAlgs), config.Clients[c].IDTokenSignedResponseAlg))
			}
		}
	default:
		if !utils.IsStringInSlice(config.Clients[c].IDTokenSignedResponseKeyID, config.Discovery.ResponseObjectSigningKeyIDs) {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
				config.Clients[c].ID, attrOIDCIDTokenSigKID, strJoinOr(config.Discovery.ResponseObjectSigningKeyIDs), config.Clients[c].IDTokenSignedResponseKeyID))
		} else {
			config.Clients[c].IDTokenSignedResponseAlg = getResponseObjectAlgFromKID(config, config.Clients[c].IDTokenSignedResponseKeyID, config.Clients[c].IDTokenSignedResponseAlg)
		}
	}
}

func validateOIDDClientSigningAlgsAccessToken(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	config.Clients[c].AccessTokenSignedResponseAlg, config.Clients[c].AccessTokenSignedResponseKeyID = validateOIDCClientAlgKIDDefault(config, config.Clients[c].AccessTokenSignedResponseAlg, config.Clients[c].AccessTokenSignedResponseKeyID, schema.DefaultOpenIDConnectClientConfiguration.AccessTokenSignedResponseAlg)

	switch config.Clients[c].AccessTokenSignedResponseKeyID {
	case "":
		switch config.Clients[c].AccessTokenSignedResponseAlg {
		case "", oidc.SigningAlgNone, oidc.SigningAlgRSAUsingSHA256:
			break
		default:
			if !utils.IsStringInSlice(config.Clients[c].AccessTokenSignedResponseAlg, config.Discovery.ResponseObjectSigningAlgs) {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
					config.Clients[c].ID, attrOIDCAccessTokenSigAlg, strJoinOr(config.Discovery.ResponseObjectSigningAlgs), config.Clients[c].AccessTokenSignedResponseAlg))
			} else {
				config.Discovery.JWTResponseAccessTokens = true
			}
		}
	default:
		switch {
		case !utils.IsStringInSlice(config.Clients[c].AccessTokenSignedResponseKeyID, config.Discovery.ResponseObjectSigningKeyIDs):
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
				config.Clients[c].ID, attrOIDCAccessTokenSigKID, strJoinOr(config.Discovery.ResponseObjectSigningKeyIDs), config.Clients[c].AccessTokenSignedResponseKeyID))
		default:
			config.Clients[c].AccessTokenSignedResponseAlg = getResponseObjectAlgFromKID(config, config.Clients[c].AccessTokenSignedResponseKeyID, config.Clients[c].AccessTokenSignedResponseAlg)
			config.Discovery.JWTResponseAccessTokens = true
		}
	}
}

func validateOIDDClientSigningAlgsUserInfo(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	config.Clients[c].UserinfoSignedResponseAlg, config.Clients[c].UserinfoSignedResponseKeyID = validateOIDCClientAlgKIDDefault(config, config.Clients[c].UserinfoSignedResponseAlg, config.Clients[c].UserinfoSignedResponseKeyID, schema.DefaultOpenIDConnectClientConfiguration.UserinfoSignedResponseAlg)

	switch config.Clients[c].UserinfoSignedResponseKeyID {
	case "":
		switch config.Clients[c].UserinfoSignedResponseAlg {
		case "", oidc.SigningAlgNone, oidc.SigningAlgRSAUsingSHA256:
			break
		default:
			if !utils.IsStringInSlice(config.Clients[c].UserinfoSignedResponseAlg, config.Discovery.ResponseObjectSigningAlgs) {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
					config.Clients[c].ID, attrOIDCUsrSigAlg, strJoinOr(append(config.Discovery.ResponseObjectSigningAlgs, oidc.SigningAlgNone)), config.Clients[c].UserinfoSignedResponseAlg))
			}
		}
	default:
		if !utils.IsStringInSlice(config.Clients[c].UserinfoSignedResponseKeyID, config.Discovery.ResponseObjectSigningKeyIDs) {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
				config.Clients[c].ID, attrOIDCUsrSigKID, strJoinOr(config.Discovery.ResponseObjectSigningKeyIDs), config.Clients[c].UserinfoSignedResponseKeyID))
		} else {
			config.Clients[c].UserinfoSignedResponseAlg = getResponseObjectAlgFromKID(config, config.Clients[c].UserinfoSignedResponseKeyID, config.Clients[c].UserinfoSignedResponseAlg)
		}
	}
}

func validateOIDDClientSigningAlgsIntrospection(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	config.Clients[c].IntrospectionSignedResponseAlg, config.Clients[c].IntrospectionSignedResponseKeyID = validateOIDCClientAlgKIDDefault(config, config.Clients[c].IntrospectionSignedResponseAlg, config.Clients[c].IntrospectionSignedResponseKeyID, schema.DefaultOpenIDConnectClientConfiguration.IntrospectionSignedResponseAlg)

	switch config.Clients[c].IntrospectionSignedResponseKeyID {
	case "":
		switch config.Clients[c].IntrospectionSignedResponseAlg {
		case "", oidc.SigningAlgNone, oidc.SigningAlgRSAUsingSHA256:
			break
		default:
			if !utils.IsStringInSlice(config.Clients[c].IntrospectionSignedResponseAlg, config.Discovery.ResponseObjectSigningAlgs) {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
					config.Clients[c].ID, attrOIDCIntrospectionSigAlg, strJoinOr(append(config.Discovery.ResponseObjectSigningAlgs, oidc.SigningAlgNone)), config.Clients[c].IntrospectionSignedResponseAlg))
			}
		}
	default:
		if !utils.IsStringInSlice(config.Clients[c].IntrospectionSignedResponseKeyID, config.Discovery.ResponseObjectSigningKeyIDs) {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
				config.Clients[c].ID, attrOIDCIntrospectionSigKID, strJoinOr(config.Discovery.ResponseObjectSigningKeyIDs), config.Clients[c].IntrospectionSignedResponseKeyID))
		} else {
			config.Clients[c].IntrospectionSignedResponseAlg = getResponseObjectAlgFromKID(config, config.Clients[c].IntrospectionSignedResponseKeyID, config.Clients[c].IntrospectionSignedResponseAlg)
		}
	}
}

func validateOIDDClientSigningAlgsJARM(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	config.Clients[c].AuthorizationSignedResponseAlg, config.Clients[c].AuthorizationSignedResponseKeyID = validateOIDCClientAlgKIDDefault(config, config.Clients[c].AuthorizationSignedResponseAlg, config.Clients[c].AuthorizationSignedResponseKeyID, schema.DefaultOpenIDConnectClientConfiguration.AuthorizationSignedResponseAlg)

	switch config.Clients[c].AuthorizationSignedResponseKeyID {
	case "":
		switch config.Clients[c].AuthorizationSignedResponseAlg {
		case "", oidc.SigningAlgNone, oidc.SigningAlgRSAUsingSHA256:
			break
		default:
			if !utils.IsStringInSlice(config.Clients[c].AuthorizationSignedResponseAlg, config.Discovery.ResponseObjectSigningAlgs) {
				validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
					config.Clients[c].ID, attrOIDCAuthorizationSigAlg, strJoinOr(config.Discovery.ResponseObjectSigningAlgs), config.Clients[c].AuthorizationSignedResponseAlg))
			}
		}
	default:
		if !utils.IsStringInSlice(config.Clients[c].AuthorizationSignedResponseKeyID, config.Discovery.ResponseObjectSigningKeyIDs) {
			validator.Push(fmt.Errorf(errFmtOIDCClientInvalidValue,
				config.Clients[c].ID, attrOIDCAuthorizationSigKID, strJoinOr(config.Discovery.ResponseObjectSigningKeyIDs), config.Clients[c].AuthorizationSignedResponseKeyID))
		} else {
			config.Clients[c].AuthorizationSignedResponseAlg = getResponseObjectAlgFromKID(config, config.Clients[c].AuthorizationSignedResponseKeyID, config.Clients[c].AuthorizationSignedResponseAlg)
		}
	}
}

func validateOIDCClientAlgKIDDefault(config *schema.IdentityProvidersOpenIDConnect, algCurrent, kidCurrent, algDefault string) (alg, kid string) {
	alg, kid = algCurrent, kidCurrent

	switch balg, bkid := len(alg) != 0, len(kid) != 0; {
	case balg && bkid:
		return
	case !balg && !bkid:
		if algDefault == "" {
			return
		}

		alg = algDefault
	}

	switch balg, bkid := len(alg) != 0, len(kid) != 0; {
	case !balg && !bkid:
		return
	case !bkid:
		for _, jwk := range config.IssuerPrivateKeys {
			if alg == jwk.Algorithm {
				kid = jwk.KeyID

				return
			}
		}
	case !balg:
		for _, jwk := range config.IssuerPrivateKeys {
			if kid == jwk.KeyID {
				alg = jwk.Algorithm

				return
			}
		}
	}

	return
}
