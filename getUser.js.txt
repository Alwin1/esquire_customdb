function getByEmail(email, callback) {
  var axios = require('axios');
  var jose  = require('node-jose');

  var nsAccountId   = configuration.netsuiteAccountId;
  var nsConsumerKey = configuration.netsuiteConsumerKey;     // Integration "Client ID"
  var nsCertId      = configuration.netsuiteCertificateId;   // Certificate ID (kid)
  var nsPrivKeyPem  = configuration.netsuitePrivateKey;      // PRIVATE key with \\n escapes in JSON
  var nsAlg         = configuration.netsuiteCertAlgorithm;

  if (!nsAccountId || !nsConsumerKey || !nsCertId || !nsPrivKeyPem) {
    return callback(new Error("Missing NetSuite configuration"));
  }

  // Normalize PEM: convert \\n to real newlines and clean up formatting
  nsPrivKeyPem = strictNormalizePem(nsPrivKeyPem, "PRIVATE KEY");

  var tokenUrl = "https://" + nsAccountId + ".suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token";
  var now = Math.floor(Date.now() / 1000);
  var payload = { iss: nsConsumerKey, scope: "rest_webservices", iat: now, exp: now + 3600, aud: tokenUrl };

  // 1) Sign client assertion
  jose.JWK.asKey(nsPrivKeyPem, "pem").then(function(key) {
    return jose.JWS
      .createSign({ format: "compact", fields: { alg: nsAlg, typ: "JWT", kid: nsCertId } }, key)
      .update(JSON.stringify(payload), "utf8").final();
  })
  // 2) Exchange for access token
  .then(function(assertion) {
    var form =
      "grant_type=client_credentials" +
      "&client_assertion_type=" + encodeURIComponent("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") +
      "&client_assertion=" + encodeURIComponent(assertion);

    return axios.post(tokenUrl, form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 10000
    });
  })
  // 3) SuiteQL: does this email exist?
  .then(function(resp) {
    var accessToken = resp && resp.data && resp.data.access_token;
    if (!accessToken) throw new Error("token response missing access_token");

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
  })
  // 4) Return Auth0 profile or null
  .then(function(resp2) {
    var items = (resp2 && resp2.data && resp2.data.items) || [];
    if (!items.length) return callback(null, null); // not found -> null profile

    var row = items[0];
    var id  = row && (row.id || (row.values && row.values.id));
    var mail = row && (row.email || (row.values && row.values.email)) || email;

    if (!id || !mail) return callback(null, null);

    // user_id must be stable & unique; prefix with a namespace
    return callback(null, { user_id: id, email: mail });
  })
  .catch(function(err) {
    var msg = (err && err.response && err.response.data) ? JSON.stringify(err.response.data)
            : (err && err.message) || String(err);
    return callback(new Error(msg));
  });

  // Helper: strict PEM normalizer (turns \\n into real newlines, rewaps 64 chars/line)
  function strictNormalizePem(pem, label) {
    var s = String(pem || "").trim();
    s = s.replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n").replace(/\r/g, "\n");
    s = s.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "");
    s = s.replace(/\s+/g, ""); // remove all whitespace
    var out = "";
    for (var i = 0; i < s.length; i += 64) out += s.substr(i, 64) + "\n";
    return "-----BEGIN " + label + "-----\n" + out + "-----END " + label + "-----\n";
  }
}
