const anonymous = {
  authenticated: false,
  access_token: '',
  refresh_token: '',
  id_token: '',
  expires_at: 0,
  displayname: ''
};

function getParameterByName(name, url) {
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
  name = name.replace(/[\[\]]/g, '\\$&');
  var results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

function Oidc(options) {
  console.log('Creating OIDC instance with options', options);
  function getUser() {
    const userString = window.sessionStorage.getItem('oidc_user');
    console.log('User string', userString);
    if (!userString || userString === 'undefined' || userString === 'null')
      return anonymous;
    const oidcUser = JSON.parse(userString);
    return oidcUser;
  }

  function redirectToAuthorize() {
    const currentUrl = encodeURIComponent(window.location.href);

    const stateObj = {
      originalUrl: currentUrl,
      clientId: options.clientId,
    };

    const encodedState = btoa(JSON.stringify(stateObj));

    window.location = `${options.authorizeEndpoint}?state=${encodedState}`;
  }

  function setUser(user) {
    //If a user is successfully found, initialize the origo component with options and user.
    if (user) {
      window.sessionStorage.setItem('oidc_user', JSON.stringify(user));
    } else {
      sessionStorage.removeItem('oidc_user');
    }
  }

  function signOut() {
    setUser(null);
    if (options.signOutUrl) {
      document.location = options.signOutUrl;
    } else {
      document.location.reload();
    }
  }

  async function getTokensByCode(code) {
    try {
      const response = await fetch(options.tokenEndpoint, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          code
        })
      });
      if (response.ok) {
        const user = await response.json();
        setUser(user);
        return;
      }
      throw 'Response from token endpoint is fail';
    } catch (e) {
      setUser(null);
      console.error('Failed getting tokens, running callback as fail.');
      throw e;
    }
  }

  async function initRefreshTimeout(timeoutInMinutes) {
    setTimeout(async () => {
      try {
        await refresh();
      } catch (e) {
        console.error('Something went wrong when refreshing at timeout', e);
      } finally {
        initRefreshTimeout(timeoutInMinutes);
      }
    }, timeoutInMinutes * 1000 * 60);
  }

  //Ask for user info, return promise. Keep it concise.
  async function verifyUser() {
    console.log('Verifying user');
    try {
      const user = getUser();
      if (!user.authenticated) {
        return;
      }
      const response = await fetch(options.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refresh_token: user.refresh_token
        })
      });
      if (response.ok) {
        console.log('cookies', response.cookies);
        console.log('headers', response.headers);
        const user = await response.json();
        setUser(user);
        return;
      }
      //If userinfo request fails throw exception so we can catch later.
      throw 'The userinfo endpoint did NOT respond with an OK http code.';
    } catch (e) {
      setUser(null);
      //If we fail completely (i.e. network error from fetch or unable to parse user as json), log error and run callback as unauthorized.
      console.error('The user could not be verified, clearing user from sessionstorage and failing.');
      throw e;
    }
  }

  async function refreshExternalSession() {
    try {
      const user = getUser();
      if (!user.authenticated) {
        return;
      }
      console.log('Refreshing external session');
      const response = await fetch(
        `${options.externalSessionUrl}?access_token=${user.access_token}`
      );
      if (response.ok) {
        console.log('cookies', response.cookies);
        console.log('headers', response.headers);
        console.info('Successfully refreshed external session');
      } else {
        throw 'External service did not respond with OK';
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function refresh() {
    try {
      await verifyUser();
      if (options.updateSessionOnRefresh) {
        await refreshExternalSession();
      }
    } catch (e) {
      console.error('Error in refresh()', e);
      throw e;
    }
  }

  async function init() {
    try {
      const queryStringCode = getParameterByName('code', window.location.href);
      const state = getParameterByName('state', window.location.href);
      const oidcUser = getUser();

      // If there's a code in the query string (callback from OIDC provider)
      if (queryStringCode) {
        await getTokensByCode(queryStringCode);

        // Decode the state to get the original URL
        if (state) {
          try {
            const decodedState = JSON.parse(window.atob(state));
            if (decodedState.originalUrl) {
              // Redirect to the original URL, including hash and query params
              console.log(`Redirecting to original URL: ${decodeURIComponent(decodedState.originalUrl)}`);
              window.location = decodeURIComponent(decodedState.originalUrl);
            } else {
              // Fallback to just removing the code and state from URL if originalUrl is not present
              removeCodeAndStateFromUrl();
            }
          } catch (error) {
            console.error('Error decoding state:', error);
            removeCodeAndStateFromUrl();
          }
        } else {
          removeCodeAndStateFromUrl();
        }

        if (options.externalSessionUrl) {
          await refreshExternalSession();
        }
      } else if (oidcUser) {
        await refresh();
      }
      initRefreshTimeout(options.sessionRefreshTimeout);
    } catch (e) {
      setUser(null);
    }
  }

  function removeCodeAndStateFromUrl() {
    const url = new URL(window.location.href);
    url.searchParams.delete('code');
    url.searchParams.delete('state');
    window.history.replaceState({}, document.title, url.toString());
  }

  return {
    getUser: getUser,
    authorize: redirectToAuthorize,
    refresh: refresh,
    signOut: signOut,
    init: init
  };
}

function createOidcAuth(options, callback) {
  const oidcInstance = new Oidc(options);
  oidcInstance.init().finally(() => callback(oidcInstance));
}

export default createOidcAuth;
