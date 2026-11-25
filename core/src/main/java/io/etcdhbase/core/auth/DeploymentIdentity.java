package io.etcdhbase.core.auth;

import io.etcdhbase.core.bytes.ByteKey;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/** Exact durable instance identity; this value is not a proof of possession. */
public record DeploymentIdentity(String trustDomain, String tableGroup, ByteKey datasetDigest,
    long memberId, String incarnation) {
  public DeploymentIdentity {
    requireIdentifier(trustDomain, "trustDomain");
    requireIdentifier(tableGroup, "tableGroup");
    Objects.requireNonNull(datasetDigest, "datasetDigest");
    if (datasetDigest.length() != 32 || memberId == 0 || incarnation == null
        || incarnation.length() > 128 || !incarnation.matches("[A-Za-z0-9._-]+")
        || incarnation.equals(".") || incarnation.equals("..")) {
      throw new IllegalArgumentException("invalid deployment identity");
    }
  }

  /** Domain-separated identity for the V1 binding row. */
  public ByteKey bindingDigest() { return digest(null); }

  /** Domain-separated identity for the V1 operation row and its exact target. */
  public ByteKey operationDigest(ByteKey operationId) {
    Objects.requireNonNull(operationId, "operationId");
    if (operationId.length() != 16) throw new IllegalArgumentException("invalid operation ID");
    return digest(operationId);
  }

  private ByteKey digest(ByteKey operationId) {
    try {
      var bytes = new ByteArrayOutputStream();
      try (var out = new DataOutputStream(bytes)) {
        out.writeUTF(operationId == null ? "etcd-hbase/deployment-binding/v1"
            : "etcd-hbase/deployment-revocation/v1");
        out.writeUTF(trustDomain);
        out.writeUTF(tableGroup);
        out.write(datasetDigest.bytes());
        out.writeLong(memberId);
        out.writeUTF(incarnation);
        if (operationId != null) out.write(operationId.bytes());
      }
      return ByteKey.copyOf(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
    } catch (IOException | NoSuchAlgorithmException failure) {
      throw new IllegalStateException("cannot derive deployment control identity", failure);
    }
  }

  private static void requireIdentifier(String value, String name) {
    if (value == null || !value.matches("[A-Za-z][A-Za-z0-9._-]{0,63}")) {
      throw new IllegalArgumentException(name + " is invalid");
    }
  }
}
