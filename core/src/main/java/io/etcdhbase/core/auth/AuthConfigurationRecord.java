package io.etcdhbase.core.auth;

import io.etcdhbase.core.bytes.ByteKey;
import java.util.Objects;

/** Operator-owned, persisted version of one table group's authorization configuration. */
public record AuthConfigurationRecord(String trustDomain, String tableGroupId,
    ByteKey configurationDigest, boolean enabled, long revision) {
  public AuthConfigurationRecord {
    if (trustDomain == null || !trustDomain.matches("[A-Za-z][A-Za-z0-9._-]{0,63}")
        || tableGroupId == null || !tableGroupId.matches("[A-Za-z][A-Za-z0-9._-]{0,63}")) {
      throw new IllegalArgumentException("invalid auth configuration binding");
    }
    Objects.requireNonNull(configurationDigest, "configurationDigest");
    if (configurationDigest.length() != 32 || revision < 1) {
      throw new IllegalArgumentException("invalid auth configuration revision or digest");
    }
  }

  /** Configuration changes advance exactly once and never change the durable record's binding. */
  public boolean permitsReplacement(AuthConfigurationRecord next) {
    return next != null && revision < Long.MAX_VALUE && next.revision == revision + 1
        && trustDomain.equals(next.trustDomain) && tableGroupId.equals(next.tableGroupId)
        && (!configurationDigest.equals(next.configurationDigest) || enabled != next.enabled);
  }
}
