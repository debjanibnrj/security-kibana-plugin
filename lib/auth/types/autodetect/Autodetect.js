/*
 * Copyright 2015-2018 _floragunn_ GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import AuthType from "../AuthType";

export default class Autodetect extends AuthType {

  constructor(pluginRoot, server, kbnServer, APP_ROOT, API_ROOT, esConfig) {
    super(pluginRoot, server, kbnServer, APP_ROOT, API_ROOT, esConfig);
    this.currentAuthClass = null;
  }

  setupChildClass(error, pluginRoot, server, kbnServer, APP_ROOT, API_ROOT, esConfig) {
      server.log(["error", "security"], "Inside The Error Constuctor Error is " + error);
      let authDirectiveStr = error["wwwAuthenticateDirective"];
      server.log(["error", "security"], "Inside Autodetect  authDirectiveStr" + authDirectiveStr);
      if (authDirectiveStr) {
        let authDirectiveArr = error["wwwAuthenticateDirective"].split(" ");
        server.log(["error", "security"], "Inside Autodetect  authDirectiveArr" + authDirectiveArr);
        if (authDirectiveArr.length > 0) {
          let authDirectiveValue = authDirectiveArr[0];
          if (!this.currentAuthClass) {
            server.log(["error", "security"], "Inside Autodetect  authDirectiveValue " + authDirectiveValue);
            switch (authDirectiveValue) {
              case 'Basic':
                let BasicAuth = require('../basicauth/BasicAuth');
                this.currentAuthClass = new BasicAuth(pluginRoot, server, kbnServer, APP_ROOT, API_ROOT, esConfig);
                break;
              case 'Bearer':
                let Jwt = require('../jwt/Jwt');
                this.currentAuthClass = new Jwt(pluginRoot, server, kbnServer, APP_ROOT, API_ROOT, esConfig);
                this.status.yellow("Security copy JWT params registered.");
                break;
              case 'X-Security-IdP':
                let Saml = require('../saml/Saml');
                this.currentAuthClass = new Saml(pluginRoot, server, kbnServer, APP_ROOT, API_ROOT, esConfig);
                break;
            }
          }
        }
      }
      this.type = this.currentAuthClass.type;
      this.authHeaderName = this.currentAuthClass.authHeaderName;
      server.log(["error", "security"], "Current Auth Type is " + this.type + "; Current Auth Class is " + this.currentAuthClass);
  }

  /**
     * Checks if we have an authorization header.
     *
     * Pass the existing session credentials to compare with the authorization header.
     *
     * @param request
     * @param sessionCredentials
     * @returns {object|null} - credentials for the authentication
     */
  detectAuthHeaderCredentials(request, sessionCredentials = null) {
    this.server.log([
      "error", "security"
    ], "Inside Autodetect detectAuthHeaderCredentials. currentAuthClass is " + this.currentAuthClass);
    return this.currentAuthClass.detectAuthHeaderCredentials(request, sessionCredentials);
  }

  async authenticate(credentials, options = {}, whitelistedHeadersAndValues, additionalAuthHeaders = {}) {
    this.server.log([
      "error", "security"
    ], "Inside Autodetect  authenticate.  currentAuthClass is " + this.currentAuthClass);
    return this.currentAuthClass.authenticate(credentials, options, whitelistedHeadersAndValues, additionalAuthHeaders);
  }

  onUnAuthenticated(request, h, error) {
    this.server.log([
      "error", "security"
    ], "Inside Autodetect  onUnAuthenticated.  currentAuthClass is " + this.currentAuthClass);
    return this.currentAuthClass.onUnAuthenticated(request, h, error);
  }

  setupRoutes() {
    this.server.log([
      "error", "security"
    ], "Inside Autodetect setupRoutes.  currentAuthClass is " + this.currentAuthClass);
    return this.currentAuthClass.setupRoutes();
  }

  async setup(server) {
    return await server.plugins.opendistro_security.getSecurityBackend()._client('opendistro_security.authinfo', {
      "headers": {
        "X-AMZN-AES-AUTH-REQUIRED": "1"
      }
    });
  }
}
