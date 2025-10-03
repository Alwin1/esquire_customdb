function login(email, password, callback) {
  var axios = require('axios');
  var jose  = require('node-jose');

  // ---- Config ----
  var auth0Domain   = String(configuration.auth0Domain || "").replace(/^https?:\/\//, "");
  var clientId      = configuration.clientId;
  var connection    = configuration.dbConnectionName || "Username-Password-Authentication";

  var nsAccountId   = configuration.netsuiteAccountId;
  var nsConsumerKey = configuration.netsuiteConsumerKey;     // NetSuite Integration "Client ID"
  var nsCertId      = configuration.netsuiteCertificateId;   // Certificate ID (kid)
  var nsPrivKeyPem  = configuration.netsuitePrivateKey;      // PRIVATE key (with \\n in JSON)
  var nsAlg         = configuration.netsuiteCertAlgorithm;

  if (!auth0Domain || !clientId || !nsAccountId || !nsConsumerKey || !nsCertId || !nsPrivKeyPem) {
    return callback(new Error("Missing configuration: auth0Domain, clientId, netsuiteAccountId, netsuiteConsumerKey, netsuiteCertificateId, netsuitePrivateKey"));
  }

  nsPrivKeyPem = strictNormalizePem(nsPrivKeyPem, "PRIVATE KEY");

  // ---- Step 1: sign client assertion (JWS) with node-jose ----
  var tokenUrl = "https://" + nsAccountId + ".suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token";
  var now      = Math.floor(Date.now() / 1000);
  var payload  = { iss: nsConsumerKey, scope: "rest_webservices", iat: now, exp: now + 3600, aud: tokenUrl };

  jose.JWK.asKey(nsPrivKeyPem, "pem").then(function(key) {
    return jose.JWS
      .createSign({ format: "compact", fields: { alg: nsAlg, typ: "JWT", kid: nsCertId } }, key)
      .update(JSON.stringify(payload), "utf8").final();
  }).then(function(assertion) {
    // ---- Step 2: exchange assertion -> NetSuite access token ----
    var form =
      "grant_type=client_credentials" +
      "&client_assertion_type=" + encodeURIComponent("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") +
      "&client_assertion=" + encodeURIComponent(assertion);

    return axios.post(tokenUrl, form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 10000
    });
  }).then(function(resp) {
    var accessToken = resp && resp.data && resp.data.access_token;
    if (!accessToken) throw new Error("token response missing access_token");

    // ---- Step 3: SuiteQL lookup (email exists?) ----
    var sanitized = String(email || "").replace(/'/g, "''");
    var query = { q: "SELECT id, email FROM contact WHERE UPPER(email) = UPPER('" + sanitized + "') AND isinactive = 'F'" };

    return axios.post(
      "https://" + nsAccountId + ".suitetalk.api.netsuite.com/services/rest/query/v1/suiteql",
      query,
      {
        headers: {
          "Authorization": "Bearer " + accessToken,
          "Content-Type": "application/json",
          "Prefer": "transient"
        },
        timeout: 10000
      }
    );
  }).then(function(resp2) {
    var data  = resp2 && resp2.data || {};
    var count = (typeof data.count === "number") ? data.count :
                (data.items && data.items.length) ? data.items.length : 0;

    if (!count) {
      // Don't reveal user existence
      return callback(new WrongUsernameOrPasswordError(email, "Invalid credentials provided."));
    }

    // ---- Step 4: trigger Auth0 reset email and block login ----
    return axios.post(
      "https://" + auth0Domain + "/dbconnections/change_password",
      { client_id: clientId, email: email, connection: connection },
      { headers: { "Content-Type": "application/json" }, timeout: 10000 }
    ).then(function() {
      return callback(new WrongUsernameOrPasswordError(
        email,
        "Reset Email Sent, Please Reset to Continue"
      ));
    });
  }).catch(function(err) {
    var msg = (err && err.response && err.response.data) ? JSON.stringify(err.response.data)
            : (err && err.message) || String(err);
    return callback(new Error(msg));
  });

  // ---- helper: strict PEM normalizer (wraps base64 at 64 chars) ----
  function strictNormalizePem(pem, label) {
    var s = String(pem || "").trim();
    // convert literal \n to real newlines
    s = s.replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n").replace(/\r/g, "\n");
    // remove header/footer if present to rebuild cleanly
    s = s.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "");
    // strip all whitespace inside base64
    s = s.replace(/\s+/g, "");
    // re-wrap to 64 chars per line
    var out = "";
    for (var i = 0; i < s.length; i += 64) out += s.substr(i, 64) + "\n";
    return "-----BEGIN " + label + "-----\n" + out + "-----END " + label + "-----\n";
  }
}
