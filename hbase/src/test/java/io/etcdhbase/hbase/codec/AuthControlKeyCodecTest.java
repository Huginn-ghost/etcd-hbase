package io.etcdhbase.hbase.codec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.etcdhbase.core.bytes.ByteKey;
import io.etcdhbase.spi.salt.HashSaltStrategy;
import io.etcdhbase.spi.salt.SaltProfile;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class AuthControlKeyCodecTest {
  private static final int SALT_WIDTH_BYTES = 2;
  private static final AuthControlKeyCodec CODEC = new AuthControlKeyCodec(
      new HashSaltStrategy(new SaltProfile(HashSaltStrategy.STRATEGY_ID, 1, 8,
          SALT_WIDTH_BYTES)));

  @Test
  void configurationAddressesSeparateDomainsAndGroups() {
    byte[] first = CODEC.configuration("trust", "group-a");
    assertArrayEquals(first, CODEC.configuration("trust", "group-a"));
    assertEquals(AuthControlKeyCodec.Kind.AUTH_CONFIGURATION, CODEC.decode(first).kind());
    assertNotEquals(ByteKey.copyOf(first), ByteKey.copyOf(CODEC.configuration("trust", "group-b")));
    assertNotEquals(ByteKey.copyOf(first), ByteKey.copyOf(CODEC.configuration("other", "group-a")));
  }

  @Test
  void sessionAndAuthorityKeysRoundTripWithTheirFullDigestIdentity() {
    ByteKey token = bytes(32, 0x5a);
    ByteKey subject = bytes(32, 0xa5);

    assertEquals(new AuthControlKeyCodec.DecodedKey(AuthControlKeyCodec.Kind.SESSION, token),
        CODEC.decode(CODEC.session(token)));
    assertEquals(new AuthControlKeyCodec.DecodedKey(
        AuthControlKeyCodec.Kind.SUBJECT_AUTHORITY, subject), CODEC.decode(CODEC.authority(subject)));
  }

  @Test
  void slotKeyUsesBigEndianIndexAndRejectsInvalidIndices() {
    int index = 0x01020304;
    byte[] row = CODEC.slot(index);
    var decoded = CODEC.decode(row);
    assertEquals(AuthControlKeyCodec.Kind.SLOT, decoded.kind());
    assertEquals(index, ByteBuffer.wrap(decoded.identity().bytes()).getInt());
    assertThrows(IllegalArgumentException.class, () -> CODEC.slot(-1));
  }

  @Test
  void deploymentNamespacesRoundTripWithoutCollidingWithExistingRecords() {
    ByteKey identity = bytes(32, 0x5a);
    byte[] binding = CODEC.deploymentBindingV1(identity);
    byte[] operation = CODEC.deploymentRevocationV1(identity);
    assertEquals(new AuthControlKeyCodec.DecodedKey(
        AuthControlKeyCodec.Kind.DEPLOYMENT_BINDING_V1, identity), CODEC.decode(binding));
    assertEquals(new AuthControlKeyCodec.DecodedKey(
        AuthControlKeyCodec.Kind.DEPLOYMENT_REVOCATION_V1, identity), CODEC.decode(operation));
    assertNotEquals(ByteKey.copyOf(binding), ByteKey.copyOf(operation));
    assertNotEquals(ByteKey.copyOf(binding), ByteKey.copyOf(CODEC.session(identity)));
    assertNotEquals(ByteKey.copyOf(binding), ByteKey.copyOf(CODEC.authority(identity)));
    assertNotEquals(ByteKey.copyOf(operation), ByteKey.copyOf(CODEC.session(identity)));
    assertNotEquals(ByteKey.copyOf(operation), ByteKey.copyOf(CODEC.authority(identity)));
    assertThrows(IllegalArgumentException.class, () -> CODEC.deploymentBindingV1(bytes(31, 1)));
    assertThrows(IllegalArgumentException.class, () -> CODEC.deploymentRevocationV1(bytes(33, 1)));
  }

  @Test
  void deploymentQualifiersSeparateIndividualBindingsAndOperations() {
    ByteKey first = bytes(32, 1);
    ByteKey second = bytes(32, 2);
    byte[] firstBinding = CODEC.deploymentBindingQualifierV1(first);
    assertArrayEquals(firstBinding, CODEC.deploymentBindingQualifierV1(first));
    assertNotEquals(ByteKey.copyOf(firstBinding),
        ByteKey.copyOf(CODEC.deploymentBindingQualifierV1(second)));
    assertNotEquals(ByteKey.copyOf(firstBinding),
        ByteKey.copyOf(CODEC.deploymentRevocationQualifierV1(first)));
    assertThrows(IllegalArgumentException.class,
        () -> CODEC.deploymentBindingQualifierV1(bytes(31, 1)));
  }

  @Test
  void rejectsWrongDigestLengthTamperedSaltAndMalformedLength() {
    assertThrows(IllegalArgumentException.class, () -> CODEC.session(bytes(31, 1)));
    byte[] row = CODEC.session(bytes(32, 2));
    row[0] ^= 1;
    assertThrows(IllegalArgumentException.class, () -> CODEC.decode(row));

    byte[] malformed = CODEC.session(bytes(32, 3));
    malformed[SALT_WIDTH_BYTES + 1 + Integer.BYTES - 1] = 0x1f;
    assertThrows(IllegalArgumentException.class, () -> CODEC.decode(malformed));
  }

  private static ByteKey bytes(int size, int value) {
    byte[] bytes = new byte[size];
    java.util.Arrays.fill(bytes, (byte) value);
    return ByteKey.copyOf(bytes);
  }
}
