//PKCE is the way
/**
 * This code takes spotify API example for PKCE oAuth2 and integrates it
 * for a future use with ESP32, only being a testing ground for what will
 * be applied for it.
 * 
 * For more information, read
 * https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow
 */



//will get clientID of user created API from json.config
const clientID = '';

//will get URL from json.config, url will be the esp32 maybe so user doesnt need to change it
const redirectUrl = window.location.href.toString();  

const authorizationEndpoint = "https://accounts.spotify.com/authorize";
const tokenEndpoint = "https://accounts.spotify.com/api/token";
const scope = 'user-read-currently-playing';

//caching token 
const currentToken = {
  get access_token() { return localStorage.getItem('access_token') || null; },
  get refresh_token() { return localStorage.getItem('refresh_token') || null; },
  get expires_in() { return localStorage.getItem('refresh_in') || null },
  get expires() { return localStorage.getItem('expires') || null },

  save: function (response) {
    const { access_token, refresh_token, expires_in } = response;
    localStorage.setItem('access_token', access_token);
    localStorage.setItem('refresh_token', refresh_token);
    localStorage.setItem('expires_in', expires_in);

    const now = new Date();
    const expiry = new Date(now.getTime() + (expires_in * 1000));
    localStorage.setItem('expires', expiry);
  }
};

//on page load, try to fetch auth code from current browser search url
const args = new URLSearchParams(window.location.search);
const code = args.get('code');

//handle callbacks
if (code) {
    const token = await getToken(code);
    currentToken.save(token);

    //refreshing
    const url = new URL(window.location.href);
    url.searchParams.delete("code");
    const updatedURL = url.search ? url.href : url.href.replace('?', '');
  window.history.replaceState({}, document.title, updatedURL);
}

if (currentToken.access_token) {
    //TODO: fetch the user data through text, no webpage for now
  const playbackState = await getPlaybackState();
  console.log(playbackState);
} else {
  //TODO: let user login on website using oAuth2 with spotify
  console.log("no token");
}

//temp function
async function loginWithSpotifyClick() {
  await redirectToSpotifyAuthorize();
}

window.loginWithSpotifyClick = loginWithSpotifyClick;

async function redirectToSpotifyAuthorize() {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const randomValues = generateRandomValues(new Uint8Array(64));
  const randomString = randomValues.reduce((acc, x) => acc + possible[x % possible.length], "");

  const code_verifier = randomString;
  const data = new TextEncoder().encode(code_verifier);
  const hashed = await hashWithSHA256(data);

  const code_challenge_base64 = btoa(String.fromCharCode(...new Uint8Array(hashed)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  window.localStorage.setItem('code_verifier', code_verifier);

  const authUrl = new URL(authorizationEndpoint)
  const params = {
    response_type: 'code',
    client_id: clientID,
    scope: scope,
    code_challenge_method: 'S256',
    code_challenge: code_challenge_base64,
    redirect_uri: redirectUrl,
  };

  authUrl.search = new URLSearchParams(params).toString();
  window.location.href = authUrl.toString(); // Redirect the user to the authorization server for login
}

function generateRandomValues(size) {
      const randomBytes = forge.random.getBytesSync(size);
      const randomArray = new Uint8Array(size);
      for (let i = 0; i < size; i++) {
          randomArray[i] = randomBytes.charCodeAt(i);
      }
      return randomArray;
} 

function hashWithSHA256(data) {
    const hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Hex);
    return hash;
}

async function getToken(code) {
  const code_verifier = localStorage.getItem('code_verifier');

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: clientID,
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUrl,
      code_verifier: code_verifier,
    }),
  });

  return await response.json();
}

//TODO: autorefresh token
async function refreshToken() {
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      client_id: clientID,
      grant_type: 'refresh_token',
      refresh_token: currentToken.refresh_token
    }),
  });

  return await response.json();
}

async function getPlaybackState() {
    const response = await fetch("https://api.spotify.com/v1/me/player/currently-playing", {
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + currentToken.access_token },
    });

  return await response.json();
}
