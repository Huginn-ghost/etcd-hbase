package io.etcdhbase.core.auth;

import io.etcdhbase.core.request.RequestScope;
import java.util.Optional;
import java.util.concurrent.CompletionStage;

/** Strong reads and exact CAS of a separately provisioned authorization configuration. */
public interface AuthConfigurationStore {
  CompletionStage<Optional<AuthConfigurationRecord>> readConfiguration(
      String tableGroupId, RequestScope scope);

  CompletionStage<Boolean> createConfigurationIfAbsent(
      AuthConfigurationRecord initial, RequestScope scope);

  CompletionStage<Boolean> compareAndSetConfiguration(
      AuthConfigurationRecord observed, AuthConfigurationRecord replacement, RequestScope scope);
}
