package io.etcdhbase.hbase.codec;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.etcdhbase.core.auth.DeploymentControlRecord;
import io.etcdhbase.core.auth.DeploymentIdentity;
import io.etcdhbase.core.bytes.ByteKey;
import io.etcdhbase.hbase.auth.proto.AuthProtos;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/** Strict, bounded V1 encoding; domain payloads still require their own validation. */
public final class DeploymentControlMessages {
  private static final int VERSION = 1;
  private static final int MAX_BYTES = 128 * 1024;

  private DeploymentControlMessages() {}

  public static byte[] encode(DeploymentControlRecord record) {
    Objects.requireNonNull(record, "record");
    DeploymentIdentity identity = record.identity();
    var content = AuthProtos.DeploymentControlContent.newBuilder().setFormatVersion(VERSION)
        .setKind(kind(record.kind())).setTrustDomain(identity.trustDomain())
        .setTableGroup(identity.tableGroup()).setDatasetDigest(bytes(identity.datasetDigest()))
        .setMemberId(identity.memberId()).setIncarnation(identity.incarnation())
        .setRevision(record.revision()).setState(state(record.state())).setPayload(bytes(record.payload()));
    record.operationId().ifPresent(id -> content.setOperationId(bytes(id)));
    byte[] encoded = content.build().toByteArray();
    byte[] envelope = AuthProtos.DeploymentControlEnvelope.newBuilder()
        .setContent(ByteString.copyFrom(encoded)).setSha256(ByteString.copyFrom(sha256(encoded)))
        .build().toByteArray();
    if (envelope.length > MAX_BYTES) throw invalid();
    return envelope;
  }

  public static DeploymentControlRecord decode(byte[] encoded) {
    if (encoded == null || encoded.length == 0 || encoded.length > MAX_BYTES) throw invalid();
    try {
      var envelope = AuthProtos.DeploymentControlEnvelope.parseFrom(encoded);
      if (!envelope.getUnknownFields().asMap().isEmpty() || !envelope.hasContent()
          || !envelope.hasSha256() || !Arrays.equals(encoded, envelope.toByteArray())) throw invalid();
      byte[] contentBytes = envelope.getContent().toByteArray();
      if (!MessageDigest.isEqual(sha256(contentBytes), envelope.getSha256().toByteArray())) throw invalid();
      var content = AuthProtos.DeploymentControlContent.parseFrom(contentBytes);
      if (!content.getUnknownFields().asMap().isEmpty()
          || !Arrays.equals(contentBytes, content.toByteArray())
          || !content.hasFormatVersion() || content.getFormatVersion() != VERSION
          || !content.hasKind() || !content.hasTrustDomain() || !content.hasTableGroup()
          || !content.hasDatasetDigest() || !content.hasMemberId() || !content.hasIncarnation()
          || !content.hasRevision() || !content.hasState() || !content.hasPayload()) throw invalid();
      var identity = new DeploymentIdentity(content.getTrustDomain(), content.getTableGroup(),
          key(content.getDatasetDigest()), content.getMemberId(), content.getIncarnation());
      return new DeploymentControlRecord(kind(content.getKind()), identity, content.getRevision(),
          state(content.getState()), content.hasOperationId()
              ? Optional.of(key(content.getOperationId())) : Optional.empty(), key(content.getPayload()));
    } catch (InvalidProtocolBufferException | IllegalArgumentException failure) {
      throw invalid();
    }
  }

  private static int kind(DeploymentControlRecord.Kind value) {
    return switch (value) { case BINDING_V1 -> 1; case REVOCATION_V1 -> 2; };
  }

  private static DeploymentControlRecord.Kind kind(int value) {
    return switch (value) {
      case 1 -> DeploymentControlRecord.Kind.BINDING_V1;
      case 2 -> DeploymentControlRecord.Kind.REVOCATION_V1;
      default -> throw invalid();
    };
  }

  private static int state(DeploymentControlRecord.State value) {
    return switch (value) { case ACTIVE -> 1; case REVOKING -> 2; case REVOKED -> 3; };
  }

  private static DeploymentControlRecord.State state(int value) {
    return switch (value) {
      case 1 -> DeploymentControlRecord.State.ACTIVE;
      case 2 -> DeploymentControlRecord.State.REVOKING;
      case 3 -> DeploymentControlRecord.State.REVOKED;
      default -> throw invalid();
    };
  }

  private static ByteString bytes(ByteKey value) { return ByteString.copyFrom(value.bytes()); }
  private static ByteKey key(ByteString value) { return ByteKey.copyOf(value.toByteArray()); }

  private static byte[] sha256(byte[] bytes) {
    try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
    catch (NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
  }

  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("deployment control record violates its format");
  }
}
