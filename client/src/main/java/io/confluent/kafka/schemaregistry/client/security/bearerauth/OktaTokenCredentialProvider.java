/*
 * Copyright 2018 Confluent Inc.
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
 */

package io.confluent.kafka.schemaregistry.client.security.bearerauth;

import io.strimzi.kafka.oauth.client.JaasClientOauthLoginCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;

import javax.security.auth.login.AppConfigurationEntry;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OktaTokenCredentialProvider implements BearerAuthCredentialProvider {
  private JaasClientOauthLoginCallbackHandler handler;

  @Override
  public String alias() {
    return "OKTA";
  }

  @Override
  public String getBearerToken(URL url) {
    OAuthBearerTokenCallback callback;
    OAuthBearerTokenCallback[] callbacks;
    try {
      callback = new OAuthBearerTokenCallback();
      callbacks = new OAuthBearerTokenCallback[1];
      callbacks[0] = callback;
      handler.handle(callbacks);
    } catch (Exception e) {
      throw new RuntimeException(
          String.format("Error getting OKTA bearer token for URL:  %s", url.toString()), e
      );

    }

    if (null == callback.errorCode()) {
      return callback.token().value();
    } else {
      throw new RuntimeException(
          String.format(
          "Error fetching OKTA token for URL: %s, error code: %s, error description: %s ",
          url.toString(),
          callback.errorCode(),
          callback.errorDescription()));
    }
  }

  @Override
  public void configure(Map<String, ?> configs) {
    try {
      handler = new JaasClientOauthLoginCallbackHandler();
      List<AppConfigurationEntry> jaasConfigEntries = new ArrayList<>();
      jaasConfigEntries.add(
                      new AppConfigurationEntry("JaasClientOauthLoginCallbackHandler",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        configs));
      handler.configure(configs, "OAUTHBEARER", jaasConfigEntries);
    } catch (Exception e) {
      throw new RuntimeException(
          String.format("Unable to load and configure OAUTH provider class: %s",
          JaasClientOauthLoginCallbackHandler.class.getName()), e);
    }
  }
}
