package io.etcdhbase.hbase.codec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.etcdhbase.core.auth.DeploymentControlRecord;
import io.etcdhbase.core.auth.DeploymentIdentity;
import io.etcdhbase.core.bytes.ByteKey;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class DeploymentControlMessagesTest {
  private final DeploymentIdentity identity = new DeploymentIdentity("trust", "group",
      ByteKey.copyOf(new byte[32]), 1, "instance");

  @Test
  void retainsIdentityAndOperationAcrossEncoding() {
    var record = new DeploymentControlRecord(DeploymentControlRecord.Kind.BINDING_V1,
        identity, 2, DeploymentControlRecord.State.REVOKING,
        Optional.of(ByteKey.copyOf(new byte[16])), ByteKey.copyOf(new byte[] {1, 2, 3}));
    assertEquals(record, DeploymentControlMessages.decode(DeploymentControlMessages.encode(record)));
  }

  @Test
  void rejectsTruncationAndCorruption() {
    var record = new DeploymentControlRecord(DeploymentControlRecord.Kind.BINDING_V1,
        identity, 1, DeploymentControlRecord.State.ACTIVE,
        Optional.empty(), ByteKey.copyOf(new byte[] {1, 2, 3}));
    byte[] bytes = DeploymentControlMessages.encode(record);
    bytes[bytes.length - 1] ^= 1;
    assertThrows(IllegalArgumentException.class, () -> DeploymentControlMessages.decode(bytes));
    assertThrows(IllegalArgumentException.class,
        () -> DeploymentControlMessages.decode(new byte[] {1}));
  }
}
