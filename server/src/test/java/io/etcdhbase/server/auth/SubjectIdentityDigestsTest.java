package io.etcdhbase.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.etcdhbase.spi.identity.AuthenticationScope;
import io.etcdhbase.spi.identity.AuthorizedBackendIdentity;
import java.util.HexFormat;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SubjectIdentityDigestsTest {
  @Test
  void verifiedSameFamilyAcrossGroupsMatchesButProviderAndDomainDoNot() {
    var a = identity("provider", "alice", "group-a");
    var b = identity("provider", "alice", "group-b");
    var family = SubjectIdentityDigests.family("trust", "realm-a", a);
    assertEquals(family, SubjectIdentityDigests.family("trust", "realm-a", b));
    assertNotEquals(family, SubjectIdentityDigests.family("trust", "realm-b", b));
    assertNotEquals(family, SubjectIdentityDigests.family("other", "realm-a", b));
    assertNotEquals(family, SubjectIdentityDigests.family("trust", "realm-a",
        identity("other-provider", "alice", "group-a")));
    assertNotEquals(family, SubjectIdentityDigests.family("trust", "realm-a",
        identity("provider", "bob", "group-a")));
    assertThrows(IllegalArgumentException.class, () -> SubjectIdentityDigests.family("trust", null, a));
  }

  @Test
  void scopedDigestKeepsTheExistingPersistedSubjectKey() {
    var digest = SubjectIdentityDigests.scoped("trust", "provider",
        new AuthenticationScope("group-a", "profile"), "alice");
    assertEquals("5da702f82268e51fd80c1043ffbf85681fb59fb0c1b675dd4bba8823451097d5",
        HexFormat.of().formatHex(digest.bytes()));
  }

  private static AuthorizedBackendIdentity identity(String provider, String subject, String group) {
    return new AuthorizedBackendIdentity(provider, subject, "opaque-reference",
        new AuthenticationScope(group, "profile"), Set.of(group), 1);
  }
}
