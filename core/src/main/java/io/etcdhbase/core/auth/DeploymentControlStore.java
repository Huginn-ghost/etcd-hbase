package io.etcdhbase.core.auth;

import io.etcdhbase.core.request.RequestScope;
import java.util.concurrent.CompletionStage;
import java.util.Optional;
import io.etcdhbase.core.bytes.ByteKey;

/** Strong-read boundary; the returned payload still requires domain-specific validation. */
public interface DeploymentControlStore {
  CompletionStage<DeploymentControlRecord> readRequired(
      DeploymentControlRecord.Kind kind, DeploymentIdentity identity,
      Optional<ByteKey> operationId, RequestScope scope);

  /** Only the separately authorized installer may be given this interface and its credentials. */
  interface Installer extends DeploymentControlStore {
    /** An exceptional completion may leave the write outcome unknown. */
    CompletionStage<Boolean> createIfAbsent(DeploymentControlRecord record, RequestScope scope);

    /**
     * Compares the exact previously observed record. An exceptional completion may leave the
     * outcome unknown: callers must use a fresh strong read and the owning domain's recovery
     * protocol. A read showing the old value does not rule out an in-flight write arriving later.
     */
    CompletionStage<Boolean> compareAndSet(
        DeploymentControlRecord observed, DeploymentControlRecord replacement, RequestScope scope);
  }
}
