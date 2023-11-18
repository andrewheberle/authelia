package handlers

import (
	"fmt"
	"net/mail"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

func TestGetWebAuthnCredentialIDFromContext(t *testing.T) {
	testCases := []struct {
		name     string
		have     any
		expected int
		err      string
	}{
		{
			"ShouldGetCredentialID",
			"5",
			5,
			"",
		},
		{
			"ShouldNotParseInt",
			5,
			0,
			"Invalid credential ID type",
		},
		{
			"ShouldNotParseAlpha",
			"abc",
			0,
			"strconv.Atoi: parsing \"abc\": invalid syntax",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)

			defer mock.Close()

			if tc.have != nil {
				mock.Ctx.SetUserValue("credentialID", tc.have)
			}

			actual, theErr := getWebAuthnCredentialIDFromContext(mock.Ctx)

			if tc.err == "" {
				assert.NoError(t, theErr)
				assert.Equal(t, tc.expected, actual)
			} else {
				assert.Equal(t, 0, actual)
				assert.EqualError(t, theErr, tc.err)
			}
		})
	}
}

func TestWebAuthnCredentialsGET(t *testing.T) {
	testCases := []struct {
		name           string
		setup          func(t *testing.T, mock *mocks.MockAutheliaCtx)
		expected       string
		expectedStatus int
		expectedf      func(t *testing.T, mock *mocks.MockAutheliaCtx)
	}{
		{
			"ShouldHandleNoCredentials",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.StorageMock.EXPECT().LoadWebAuthnCredentialsByUsername(mock.Ctx, exampleDotCom, testUsername).Return(nil, storage.ErrNoWebAuthnCredential)
			},
			`{"status":"OK","data":null}`,
			fasthttp.StatusOK,
			nil,
		},
		{
			"ShouldHandleAnonymous",
			nil,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred loading WebAuthn credentials", "user is anonymous")
			},
		},
		{
			"ShouldHandleBadOrigin",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.Ctx.Request.Header.Set("X-Original-URL", "haoiu123!J@#*()!@HJ$!@*(OJOIFQJNW()D@JE()_@JK")
			},
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred loading WebAuthn credentials for user 'john': error occurred attempting to retrieve origin", "failed to parse X-Original-URL header: parse \"haoiu123!J@#*()!@HJ$!@*(OJOIFQJNW()D@JE()_@JK\": invalid URI for request")
			},
		},
		{
			"ShouldHandleStorageError",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.StorageMock.EXPECT().LoadWebAuthnCredentialsByUsername(mock.Ctx, exampleDotCom, testUsername).Return(nil, fmt.Errorf("bad block"))
			},
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred loading WebAuthn credentials for user 'john'", "bad block")
			},
		},
		{
			"ShouldHandleCredentials",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.StorageMock.EXPECT().LoadWebAuthnCredentialsByUsername(mock.Ctx, exampleDotCom, testUsername).Return([]model.WebAuthnCredential{{ID: 1}}, nil)
			},
			"{\"status\":\"OK\",\"data\":[{\"id\":1,\"created_at\":\"0001-01-01T00:00:00Z\",\"rpid\":\"\",\"username\":\"\",\"description\":\"\",\"kid\":\"\",\"attestation_type\":\"\",\"attachment\":\"\",\"transports\":null,\"sign_count\":0,\"clone_warning\":false,\"discoverable\":false,\"present\":false,\"verified\":false,\"backup_eligible\":false,\"backup_state\":false,\"public_key\":\"\"}]}",
			fasthttp.StatusOK,
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)

			defer mock.Close()

			if tc.setup != nil {
				tc.setup(t, mock)
			}

			WebAuthnCredentialsGET(mock.Ctx)

			assert.Equal(t, tc.expectedStatus, mock.Ctx.Response.StatusCode())
			assert.Equal(t, tc.expected, string(mock.Ctx.Response.Body()))

			if tc.expectedf != nil {
				tc.expectedf(t, mock)
			}
		})
	}
}

func TestWebAuthnCredentialsPUT(t *testing.T) {
	testCases := []struct {
		name           string
		setup          func(t *testing.T, mock *mocks.MockAutheliaCtx)
		have           string
		expected       string
		expectedStatus int
		expectedf      func(t *testing.T, mock *mocks.MockAutheliaCtx)
	}{
		{
			"ShouldHandleSuccessfulAdjustment",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.StorageMock.EXPECT().LoadWebAuthnCredentialByID(mock.Ctx, 1).Return(&model.WebAuthnCredential{ID: 1, Username: testUsername}, nil)
				mock.StorageMock.EXPECT().UpdateWebAuthnCredentialDescription(mock.Ctx, testUsername, 1, "abc").Return(nil)
			},
			`{"description":"abc"}`,
			`{"status":"OK"}`,
			fasthttp.StatusOK,
			nil,
		},
		{
			"ShouldHandleAnotherUser",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.StorageMock.EXPECT().LoadWebAuthnCredentialByID(mock.Ctx, 1).Return(&model.WebAuthnCredential{ID: 1, Username: "anotheruser"}, nil)
			},
			`{"description":"abc"}`,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred modifying WebAuthn credential for user 'john'", "user 'anotheruser' owns the credential with id '1'")
			},
		},
		{
			"ShouldHandleFailUpdate",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.StorageMock.EXPECT().LoadWebAuthnCredentialByID(mock.Ctx, 1).Return(&model.WebAuthnCredential{ID: 1, Username: testUsername}, nil)
				mock.StorageMock.EXPECT().UpdateWebAuthnCredentialDescription(mock.Ctx, testUsername, 1, "abc").Return(fmt.Errorf("gremlin"))
			},
			`{"description":"abc"}`,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred modifying WebAuthn credential for user 'john': error occurred while attempting to save the modified credential in storage", "gremlin")
			},
		},
		{
			"ShouldHandleFailLoad",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.StorageMock.EXPECT().LoadWebAuthnCredentialByID(mock.Ctx, 1).Return(nil, fmt.Errorf("deleted"))
			},
			`{"description":"abc"}`,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred modifying WebAuthn credential for user 'john': error occurred trying to load the credential", "deleted")
			},
		},
		{
			"ShouldHandleBadJSON",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))
			},
			`{"description:"abc"}`,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusBadRequest,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred modifying WebAuthn credential: error occurred parsing the form data", "invalid character 'a' after object key")
			},
		},
		{
			"ShouldHandleBadDescription",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))
			},
			`{"description":""}`,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred modifying WebAuthn credential for user 'john", "description is empty")
			},
		},
		{
			"ShouldHandleAnonymous",
			nil,
			`{"description":"abc"}`,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred modifying WebAuthn credential", "user is anonymous")
			},
		},
		{
			"ShouldHandleBadID",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.Ctx.SetUserValue("credentialID", "a")
			},
			`{"description":"abc"}`,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusBadRequest,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred modifying WebAuthn credential for user 'john': error occurred trying to determine the credential ID", "strconv.Atoi: parsing \"a\": invalid syntax")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)

			defer mock.Close()

			mock.Ctx.SetUserValue("credentialID", "1")
			mock.Ctx.Request.SetBodyString(tc.have)

			if tc.setup != nil {
				tc.setup(t, mock)
			}

			WebAuthnCredentialPUT(mock.Ctx)

			assert.Equal(t, tc.expectedStatus, mock.Ctx.Response.StatusCode())
			assert.Equal(t, tc.expected, string(mock.Ctx.Response.Body()))

			if tc.expectedf != nil {
				tc.expectedf(t, mock)
			}
		})
	}
}

func TestWebAuthnCredentialsDELETE(t *testing.T) {
	testCases := []struct {
		name           string
		setup          func(t *testing.T, mock *mocks.MockAutheliaCtx)
		expected       string
		expectedStatus int
		expectedf      func(t *testing.T, mock *mocks.MockAutheliaCtx)
	}{
		{
			"ShouldHandleSuccessfulDelete",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				gomock.InOrder(
					mock.StorageMock.EXPECT().
						LoadWebAuthnCredentialByID(mock.Ctx, 1).
						Return(&model.WebAuthnCredential{ID: 1, Username: testUsername, KID: model.NewBase64([]byte("abc"))}, nil),
					mock.StorageMock.EXPECT().
						DeleteWebAuthnCredential(mock.Ctx, model.NewBase64([]byte("abc")).String()).
						Return(nil),
					mock.UserProviderMock.EXPECT().
						GetDetails(testUsername).
						Return(&authentication.UserDetails{Username: testUsername, DisplayName: testDisplayName, Emails: []string{"john@example.com"}}, nil),
					mock.NotifierMock.EXPECT().
						Send(mock.Ctx, mail.Address{Name: testDisplayName, Address: "john@example.com"}, "Second Factor Method Removed", gomock.Any(), gomock.Any()).
						Return(nil),
				)
			},
			`{"status":"OK"}`,
			fasthttp.StatusOK,
			nil,
		},
		{
			"ShouldHandleSuccessfulDeleteWithNotifierError",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				gomock.InOrder(
					mock.StorageMock.EXPECT().
						LoadWebAuthnCredentialByID(mock.Ctx, 1).
						Return(&model.WebAuthnCredential{ID: 1, Username: testUsername, KID: model.NewBase64([]byte("abc"))}, nil),
					mock.StorageMock.EXPECT().
						DeleteWebAuthnCredential(mock.Ctx, model.NewBase64([]byte("abc")).String()).
						Return(nil),
					mock.UserProviderMock.EXPECT().
						GetDetails(testUsername).
						Return(&authentication.UserDetails{Username: testUsername, DisplayName: testDisplayName, Emails: []string{"john@example.com"}}, nil),
					mock.NotifierMock.EXPECT().
						Send(mock.Ctx, mail.Address{Name: testDisplayName, Address: "john@example.com"}, "Second Factor Method Removed", gomock.Any(), gomock.Any()).
						Return(fmt.Errorf("bad conn")),
				)
			},
			`{"status":"OK"}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred sending notification to user 'john' while attempting to notify them of an important event", "bad conn")
			},
		},
		{
			"ShouldHandleSuccessfulDeleteWithUserError",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				gomock.InOrder(
					mock.StorageMock.EXPECT().
						LoadWebAuthnCredentialByID(mock.Ctx, 1).
						Return(&model.WebAuthnCredential{ID: 1, Username: testUsername, KID: model.NewBase64([]byte("abc"))}, nil),
					mock.StorageMock.EXPECT().
						DeleteWebAuthnCredential(mock.Ctx, model.NewBase64([]byte("abc")).String()).
						Return(nil),
					mock.UserProviderMock.EXPECT().
						GetDetails(testUsername).
						Return(nil, fmt.Errorf("bad user")),
				)
			},
			`{"status":"OK"}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred looking up user details for user 'john' while attempting to notify them of an important event", "bad user")
			},
		},
		{
			"ShouldHandleFailedDeleteStorage",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				gomock.InOrder(
					mock.StorageMock.EXPECT().
						LoadWebAuthnCredentialByID(mock.Ctx, 1).
						Return(&model.WebAuthnCredential{ID: 1, Username: testUsername, KID: model.NewBase64([]byte("abc"))}, nil),
					mock.StorageMock.EXPECT().
						DeleteWebAuthnCredential(mock.Ctx, model.NewBase64([]byte("abc")).String()).
						Return(fmt.Errorf("bad pipe")),
				)
			},
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred delete WebAuthn credential for user 'john': error occurred while attempting to delete the credential from storage", "bad pipe")
			},
		},
		{
			"ShouldHandleFailedLoadStorage",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				gomock.InOrder(
					mock.StorageMock.EXPECT().
						LoadWebAuthnCredentialByID(mock.Ctx, 1).
						Return(nil, fmt.Errorf("bad sql password")),
				)
			},
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred deleting WebAuthn credential for user 'john': error occurred trying to load the credential", "bad sql password")
			},
		},
		{
			"ShouldHandleBadUser",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				gomock.InOrder(
					mock.StorageMock.EXPECT().
						LoadWebAuthnCredentialByID(mock.Ctx, 1).
						Return(&model.WebAuthnCredential{ID: 1, Username: "baduser", KID: model.NewBase64([]byte("abc"))}, nil),
				)
			},
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred deleting WebAuthn credential for user 'john'", "user 'baduser' owns the credential with id '1'")
			},
		},
		{
			"ShouldHandleBadID",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				us, err := mock.Ctx.GetSession()

				require.NoError(t, err)

				us.Username = testUsername
				us.AuthenticationLevel = authentication.OneFactor

				require.NoError(t, mock.Ctx.SaveSession(us))

				mock.Ctx.SetUserValue("credentialID", "a")
			},
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusBadRequest,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred deleting WebAuthn credential: error occurred trying to determine the credential ID", "strconv.Atoi: parsing \"a\": invalid syntax")
			},
		},
		{
			"ShouldHandleAnonymous",
			nil,
			`{"status":"KO","message":"Operation failed."}`,
			fasthttp.StatusOK,
			func(t *testing.T, mock *mocks.MockAutheliaCtx) {
				AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), "Error occurred modifying WebAuthn credential", "user is anonymous")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)

			defer mock.Close()

			mock.Ctx.SetUserValue("credentialID", "1")

			if tc.setup != nil {
				tc.setup(t, mock)
			}

			WebAuthnCredentialDELETE(mock.Ctx)

			assert.Equal(t, tc.expectedStatus, mock.Ctx.Response.StatusCode())
			assert.Equal(t, tc.expected, string(mock.Ctx.Response.Body()))

			if tc.expectedf != nil {
				tc.expectedf(t, mock)
			}
		})
	}
}
