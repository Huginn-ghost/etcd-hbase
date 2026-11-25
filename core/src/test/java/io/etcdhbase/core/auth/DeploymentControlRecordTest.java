package io.etcdhbase.core.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.etcdhbase.core.bytes.ByteKey;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class DeploymentControlRecordTest {
  private static final ByteKey DATASET = ByteKey.copyOf(new byte[32]);
  private static final ByteKey OPERATION = ByteKey.copyOf(new byte[16]);
  private static final ByteKey PAYLOAD = ByteKey.copyOf(new byte[] {1});
  private static final DeploymentIdentity IDENTITY =
      new DeploymentIdentity("trust", "group", DATASET, 1, "incarnation");

  @Test
  void exactIdentityIncludesDatasetGroupMemberAndIncarnation() {
    var otherDataset = ByteKey.copyOf(new byte[32]);
    byte[] differentBytes = otherDataset.bytes();
    differentBytes[0] = 1;
    assertNotEquals(IDENTITY.bindingDigest(), new DeploymentIdentity(
        "trust", "group", ByteKey.copyOf(differentBytes), 1, "incarnation").bindingDigest());
    assertNotEquals(IDENTITY.bindingDigest(), new DeploymentIdentity(
        "trust", "other", DATASET, 1, "incarnation").bindingDigest());
    assertNotEquals(IDENTITY.bindingDigest(), new DeploymentIdentity(
        "trust", "group", DATASET, 2, "incarnation").bindingDigest());
    assertNotEquals(IDENTITY.bindingDigest(), new DeploymentIdentity(
        "trust", "group", DATASET, 1, "other").bindingDigest());
    assertNotEquals(IDENTITY.bindingDigest(), new DeploymentIdentity(
        "other", "group", DATASET, 1, "incarnation").bindingDigest());
    assertNotEquals(IDENTITY.bindingDigest(), IDENTITY.operationDigest(OPERATION));
    assertEquals(IDENTITY.bindingDigest(), IDENTITY.bindingDigest());
  }

  @Test
  void revocationOperationCannotBeLostOrReplacedDuringCasProgress() {
    var active = record(1, DeploymentControlRecord.State.ACTIVE, Optional.empty());
    var revoking = record(2, DeploymentControlRecord.State.REVOKING, Optional.of(OPERATION));
    var next = record(3, DeploymentControlRecord.State.REVOKED, Optional.of(OPERATION));
    assertTrue(active.isInitial());
    assertFalse(revoking.isInitial());
    assertTrue(active.allowsReplacement(revoking));
    assertTrue(revoking.allowsReplacement(next));
    assertFalse(next.allowsReplacement(record(4, DeploymentControlRecord.State.ACTIVE, Optional.empty())));
    assertFalse(active.allowsReplacement(record(2, DeploymentControlRecord.State.REVOKED,
        Optional.of(OPERATION))));
    assertFalse(revoking.allowsReplacement(record(2, DeploymentControlRecord.State.REVOKED,
        Optional.of(OPERATION))));
    var otherDataset = new byte[32];
    otherDataset[0] = 1;
    var otherIdentity = new DeploymentIdentity("trust", "group", ByteKey.copyOf(otherDataset),
        1, "incarnation");
    assertFalse(active.allowsReplacement(new DeploymentControlRecord(active.kind(), otherIdentity, 2,
        DeploymentControlRecord.State.REVOKING, Optional.of(OPERATION), PAYLOAD)));
    byte[] other = new byte[16];
    other[0] = 1;
    assertFalse(revoking.allowsReplacement(record(3, DeploymentControlRecord.State.REVOKING,
        Optional.of(ByteKey.copyOf(other)))));
    assertFalse(revoking.allowsReplacement(record(4, DeploymentControlRecord.State.REVOKING,
        Optional.of(OPERATION))));
    assertThrows(IllegalArgumentException.class, () -> record(3,
        DeploymentControlRecord.State.REVOKING, Optional.empty()));
    assertThrows(IllegalArgumentException.class, () -> new DeploymentControlRecord(
        DeploymentControlRecord.Kind.REVOCATION_V1, IDENTITY, 1,
        DeploymentControlRecord.State.REVOKING, Optional.empty(), PAYLOAD));
  }

  private static DeploymentControlRecord record(long revision, DeploymentControlRecord.State state,
      Optional<ByteKey> operationId) {
    return new DeploymentControlRecord(DeploymentControlRecord.Kind.BINDING_V1,
        IDENTITY, revision, state, operationId, PAYLOAD);
  }
}
