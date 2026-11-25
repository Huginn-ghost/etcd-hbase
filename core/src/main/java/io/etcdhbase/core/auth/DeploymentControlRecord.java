package io.etcdhbase.core.auth;

import io.etcdhbase.core.bytes.ByteKey;
import java.util.Objects;
import java.util.Optional;

/** Versioned envelope for deployment-owned records in the authentication-control table.
 * The payload and its authorization semantics are validated by the owning domain.
 */
public record DeploymentControlRecord(Kind kind, DeploymentIdentity identity, long revision,
    State state, Optional<ByteKey> operationId, ByteKey payload) {
  public static final int MAX_PAYLOAD_BYTES = 64 * 1024;

  public enum Kind { BINDING_V1, REVOCATION_V1 }
  public enum State { ACTIVE, REVOKING, REVOKED }

  public DeploymentControlRecord {
    Objects.requireNonNull(kind, "kind");
    Objects.requireNonNull(identity, "identity");
    Objects.requireNonNull(state, "state");
    Objects.requireNonNull(operationId, "operationId");
    Objects.requireNonNull(payload, "payload");
    if (revision < 1
        || payload.length() < 1 || payload.length() > MAX_PAYLOAD_BYTES
        || operationId.filter(value -> value.length() != 16).isPresent()
        || (state == State.ACTIVE) != operationId.isEmpty()
        || kind == Kind.REVOCATION_V1 && state == State.ACTIVE) {
      throw new IllegalArgumentException("invalid deployment control record");
    }
  }

  public ByteKey identityDigest() {
    return kind == Kind.BINDING_V1 ? identity.bindingDigest()
        : identity.operationDigest(operationId.orElseThrow());
  }

  public boolean isInitial() {
    return revision == 1 && (kind == Kind.BINDING_V1 && state == State.ACTIVE
        || kind == Kind.REVOCATION_V1 && state == State.REVOKING);
  }

  /** Keeps the operation ID durable across retries and forbids replacing one operation with another. */
  public boolean allowsReplacement(DeploymentControlRecord next) {
    return next != null && kind == next.kind && identity.equals(next.identity)
        && revision < Long.MAX_VALUE && next.revision == revision + 1
        && switch (state) {
          case ACTIVE -> next.state == State.REVOKING;
          case REVOKING -> (next.state == State.REVOKING || next.state == State.REVOKED)
              && operationId.equals(next.operationId);
          case REVOKED -> false;
        };
  }
}
