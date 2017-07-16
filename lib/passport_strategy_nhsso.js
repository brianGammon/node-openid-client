'use strict';

/* eslint-disable no-underscore-dangle */

const _ = require('lodash');
const uuid = require('uuid');
const url = require('url');
const assert = require('assert');
const OpenIdConnectError = require('./open_id_connect_error');
const Client = require('./client');

function verified(err, user, info) {
  const add = info || {};
  if (err) {
    this.error(err);
  } else if (!user) {
    this.fail(add);
  } else {
    this.success(user, add);
  }
}

/**
 * @name constructor
 * @api public
 * 
 * This is a simplified version of the passport strategy provided in the openid-client package.
 * 
 * This version requires the Client instance to be supplied on the Express.js req object, allowing
 * the ability to support multiple client apps with one passport stategy.
 * 
 * There are no changes to the core openid-client library, only the addition of this file and a 
 * corresponding test file.
 * 
 * The lib/index.js was modified to include this Stategy in the exports for the package
 */
function NhssoOpenIDConnectStrategy(verify) {
  assert.equal(typeof verify, 'function');
  this._verify = verify;
}

NhssoOpenIDConnectStrategy.prototype.authenticate = function authenticate(req) {
  if (!(req.client && req.client instanceof Client)) {
    this.error(new Error('Must provide an instance of Client on req object.'));
    return;
  } 
  const client = req.client;
  const issuer = client.issuer;
  let settings = {};

  settings.response_type = _.get(client, 'response_types[0]', 'code');
  settings.redirect_uri = _.get(client, 'redirect_uris[0]');
  settings.scope = _.get(client, 'scopes[0]', 'openid');
  settings.response_mode = _.get(client, 'response_mode');
  
  try {
    if (!req.session) throw new Error('authentication requires session support when using state or nonce');
    const reqParams = client.callbackParams(req);
    const sessionKey = `oidc:${url.parse(issuer.issuer).hostname}:${client.client_id}`;

    /* start authentication request */
    if (_.isEmpty(reqParams)) {
      // BG July 2017
      // state: uuid()
      // state: 'eyJJRnJhbWVUYXJnZXQiOiJfZG9uZSJ9'
      const opts = _.defaults({}, settings, {
        state: 'eyJJRnJhbWVUYXJnZXQiOiJfZG9uZSJ9',
      });

      if (!opts.nonce && opts.response_type.includes('id_token')) {
        opts.nonce = uuid();
      }
      req.session[sessionKey] = _.pick(opts, 'nonce', 'state');
      this.redirect(client.authorizationUrl(opts));
      return;
    }
    /* end authentication request */

    /* start authentication response */
    const session = req.session[sessionKey];
    const state = _.get(session, 'state');
    const nonce = _.get(session, 'nonce');

    try {
      delete req.session[sessionKey];
    } catch (err) {}

    const checks = { state, nonce };
    let callback = client.authorizationCallback(settings.redirect_uri, reqParams, checks)
      .then((tokenset) => {
        const result = { tokenset };
        return result;
      });

    const loadUserinfo = this._verify.length > 2 && client.issuer.userinfo_endpoint;

    if (loadUserinfo) {
      callback = callback.then((result) => {
        if (result.tokenset.access_token) {
          const userinfoRequest = client.userinfo(result.tokenset);
          return userinfoRequest.then((userinfo) => {
            result.userinfo = userinfo;
            return result;
          });
        }

        return result;
      });
    }

    callback.then((result) => {
      if (loadUserinfo) {
        this._verify(result.tokenset, result.userinfo, verified.bind(this));
      } else {
        this._verify(result.tokenset, verified.bind(this));
      }
    }).catch((error) => {
      if (error instanceof OpenIdConnectError &&
            error.error !== 'server_error' &&
            !error.error.startsWith('invalid')) {
        this.fail(error);
      } else {
        this.error(error);
      }
    });
    /* end authentication response */
  } catch (err) {
    this.error(err);
  }
};

module.exports = NhssoOpenIDConnectStrategy;
