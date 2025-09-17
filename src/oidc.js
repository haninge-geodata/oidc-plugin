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
  function getUser() {
    const userString = window.sessionStorage.getItem('oidc_user');
    if (!userString || userString === 'undefined' || userString === 'null') return anonymous;
    const oidcUser = JSON.parse(userString);
    return oidcUser;
  }

  function redirectToAuthorize() {
    window.location = `${options.authorizeEndpoint}?state=${options.clientId}&redirectUrl=${options.redirectUrl}`;
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
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          code,
          redirectUrl: options.redirectUrl
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
      const response = await fetch(`${options.externalSessionUrl}?access_token=${user.access_token}`);
      if (response.ok) {
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
      const oidcUser = getUser();

      //If there was a user in session storage
      if (queryStringCode) {
        await getTokensByCode(queryStringCode);
        window.history.replaceState({}, document.title, window.location.pathname);
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
