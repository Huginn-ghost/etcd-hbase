package io.etcdhbase.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import etcdserverpb.Rpc;
import io.etcdhbase.core.auth.AuthSession;
import io.etcdhbase.core.auth.AuthConfigurationRecord;
import io.etcdhbase.core.auth.AuthConfigurationStore;
import io.etcdhbase.core.auth.AuthDeploymentRegistry;
import io.etcdhbase.core.auth.AuthDeploymentRegistryStore;
import io.etcdhbase.core.auth.TargetAuthorizationBarriers;
import io.etcdhbase.core.auth.TargetConfigurationBarriers;
import io.etcdhbase.core.auth.AuthSessionException;
import io.etcdhbase.core.auth.AuthSessionStore;
import io.etcdhbase.core.auth.AuthSlot;
import io.etcdhbase.core.auth.CredentialEnvelope;
import io.etcdhbase.core.auth.SubjectAuthority;
import io.etcdhbase.core.bytes.ByteKey;
import io.etcdhbase.core.commit.AuthorizationBarrierInstaller;
import io.etcdhbase.core.commit.CommitControlStore;
import io.etcdhbase.core.commit.CommitState;
import io.etcdhbase.core.commit.ControlSnapshot;
import io.etcdhbase.core.error.BackendFailure;
import io.etcdhbase.core.request.RequestScope;
import io.etcdhbase.spi.identity.AuthenticationScope;
import io.etcdhbase.spi.identity.AuthorizedBackendIdentity;
import io.etcdhbase.spi.identity.BackendCredentials;
import io.etcdhbase.spi.identity.BackendIdentityException;
import io.grpc.stub.StreamObserver;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthSessionServiceTest {
  private static final AuthenticationScope SCOPE = new AuthenticationScope("group", "profile");
  private static final ByteKey DATASET = key(32, 9);

  @TempDir Path temporary;

  @Test
  void localServicesCooperativelyRecoverConfigurationBarriers() throws Exception {
    var store = new FakeStore();
    var scopeB = new AuthenticationScope("other", "profile");
    var datasetB = key(32, 10);
    var digestA = key(32, 20);
    var digestB = key(32, 21);
    var groupA = new AuthDeploymentRegistry.Group("group", "hbase-provider", "realm", "profile",
        DATASET, digestA, true);
    var groupB = new AuthDeploymentRegistry.Group("other", "hbase-provider", "realm", "profile",
        datasetB, digestB, true);
    var registry = new FakeDeploymentRegistry(AuthDeploymentRegistry.initial("milvus", java.util.List.of(groupA, groupB))
        .beginConfigurationUpdate(java.util.List.of(groupA)));
    var fixedClock = Clock.fixed(Instant.ofEpochMilli(20), ZoneOffset.UTC);
    var installerA = new AuthorizationBarrierInstaller(new FakeControlStore(), fixedClock);
    var installerB = new AuthorizationBarrierInstaller(new FakeControlStore(), fixedClock);
    var revocationA = new TargetAuthorizationBarriers(store, "milvus", Map.of("group",
        new TargetAuthorizationBarriers.Group("hbase-provider", SCOPE, DATASET, installerA)));
    var revocationB = new TargetAuthorizationBarriers(store, "milvus", Map.of("other",
        new TargetAuthorizationBarriers.Group("hbase-provider", scopeB, datasetB, installerB)));
    var configurationA = new TargetConfigurationBarriers(Map.of("group",
        new TargetConfigurationBarriers.Group(DATASET, installerA)));
    var configurationB = new TargetConfigurationBarriers(Map.of("other",
        new TargetConfigurationBarriers.Group(datasetB, installerB)));
    try (var keys = keyProvider("key-1", temporary.resolve("configuration-recovery-key.bin"));
        var request = RequestScope.withTimeout(Duration.ofSeconds(10))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      var a = new AuthSessionService(store, protector, new FakeIdentityManager(), "milvus", "hbase-provider",
          SCOPE, DATASET, Duration.ofMinutes(5), 4, Clock.systemUTC(), new SecureRandom(),
          registry, revocationA, "realm", digestA, Set.of("group"), configurationA);
      var b = new AuthSessionService(store, protector, new FakeIdentityManager(), "milvus", "hbase-provider",
          scopeB, datasetB, Duration.ofMinutes(5), 4, Clock.systemUTC(), new SecureRandom(),
          registry, revocationB, "realm", digestB, Set.of("other"), configurationB);
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> a.resumePendingDeploymentRevocation(request).toCompletableFuture().get());
      assertEquals(1, registry.current.configurationGeneration());
      assertTrue(registry.current.configurationUpdate().targets().getFirst().installed());
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> a.readAuthConfiguration(request).toCompletableFuture().get());
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> b.resumePendingDeploymentRevocation(request).toCompletableFuture().get());
      assertEquals(2, registry.current.configurationGeneration());
      assertEquals(java.util.List.of(groupA), registry.current.groups());
      assertEquals(2, a.readAuthConfiguration(request).toCompletableFuture().get().revision());
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> b.readAuthConfiguration(request).toCompletableFuture().get());
    }
  }

  @Test
  void independentGroupServicesResumeOnlyTheirOwnRegisteredBarriers() throws Exception {
    var store = new FakeStore();
    var scopeB = new AuthenticationScope("other", "profile");
    var datasetB = key(32, 10);
    var digestA = key(32, 20);
    var digestB = key(32, 21);
    var groupA = new AuthDeploymentRegistry.Group("group", "hbase-provider", "realm", "profile",
        DATASET, digestA, true);
    var groupB = new AuthDeploymentRegistry.Group("other", "hbase-provider", "realm", "profile",
        datasetB, digestB, true);
    var registry = new FakeDeploymentRegistry(AuthDeploymentRegistry.initial("milvus", java.util.List.of(groupA, groupB)));
    var fixedClock = Clock.fixed(Instant.ofEpochMilli(20), ZoneOffset.UTC);
    var barriersA = new TargetAuthorizationBarriers(store, "milvus", Map.of("group",
        new TargetAuthorizationBarriers.Group("hbase-provider", SCOPE, DATASET,
            new AuthorizationBarrierInstaller(new FakeControlStore(), fixedClock))));
    var barriersB = new TargetAuthorizationBarriers(store, "milvus", Map.of("other",
        new TargetAuthorizationBarriers.Group("hbase-provider", scopeB, datasetB,
            new AuthorizationBarrierInstaller(new FakeControlStore(), fixedClock))));
    try (var keys = keyProvider("key-1", temporary.resolve("independent-group-key.bin"));
        var request = RequestScope.withTimeout(Duration.ofSeconds(10));
        var credential = credentials()) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      var a = new AuthSessionService(store, protector, new FakeIdentityManager(), "milvus", "hbase-provider",
          SCOPE, DATASET, Duration.ofMinutes(5), 4, Clock.systemUTC(), new SecureRandom(),
          registry, barriersA, "realm", digestA, Set.of("group"));
      var b = new AuthSessionService(store, protector, new FakeIdentityManager(), "milvus", "hbase-provider",
          scopeB, datasetB, Duration.ofMinutes(5), 4, Clock.systemUTC(), new SecureRandom(),
          registry, barriersB, "realm", digestB, Set.of("other"));
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> a.authenticate(credential, request).toCompletableFuture().get());
      assertTrue(registry.current.revocation().targets().get(0).installed());
      assertFalse(registry.current.revocation().targets().get(1).installed());
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> b.resumePendingDeploymentRevocation(request).toCompletableFuture().get());
      assertFalse(registry.current.revocation().targets().get(0).released());
      a.resumePendingDeploymentRevocation(request).toCompletableFuture().get();
      var token = a.authenticate(credential, request).toCompletableFuture().get();
      var resolved = a.resolve(token.tokenForResponse(), request).toCompletableFuture().get();
      resolved.release().toCompletableFuture().get();
    }
  }

  @Test
  void deploymentRotationBlocksBothGroupsUntilTheirBarriersComplete() throws Exception {
    var store = new FakeStore();
    var profileB = new AuthenticationScope("other", "profile");
    var datasetB = key(32, 10);
    var digestA = key(32, 20);
    var digestB = key(32, 21);
    var groupA = new AuthDeploymentRegistry.Group("group", "hbase-provider", "realm", "profile",
        DATASET, digestA, true);
    var groupB = new AuthDeploymentRegistry.Group("other", "hbase-provider", "realm", "profile",
        datasetB, digestB, true);
    var registry = new FakeDeploymentRegistry(AuthDeploymentRegistry.initial("milvus", java.util.List.of(groupA, groupB)));
    var controlA = new FakeControlStore();
    var controlB = new FakeControlStore();
    var fixedClock = Clock.fixed(Instant.ofEpochMilli(20), ZoneOffset.UTC);
    var barriers = new TargetAuthorizationBarriers(store, "milvus", Map.of(
        "group", new TargetAuthorizationBarriers.Group("hbase-provider", SCOPE, DATASET,
            new AuthorizationBarrierInstaller(controlA, fixedClock)),
        "other", new TargetAuthorizationBarriers.Group("hbase-provider", profileB, datasetB,
            new AuthorizationBarrierInstaller(controlB, fixedClock))));
    var identitiesA = new FakeIdentityManager();
    var identitiesB = new FakeIdentityManager();
    try (var keys = keyProvider("key-1", temporary.resolve("deployment-key.bin"));
        var request = RequestScope.withTimeout(Duration.ofSeconds(10));
        var credential = credentials()) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      var a = new AuthSessionService(store, protector, identitiesA, "milvus", "hbase-provider",
          SCOPE, DATASET, Duration.ofMinutes(5), 4, Clock.systemUTC(), new SecureRandom(),
          registry, barriers, "realm", digestA);
      var b = new AuthSessionService(store, protector, identitiesB, "milvus", "hbase-provider",
          profileB, datasetB, Duration.ofMinutes(5), 4, Clock.systemUTC(), new SecureRandom(),
          registry, barriers, "realm", digestB);
      var oldA = a.authenticate(credential, request).toCompletableFuture().get();
      var oldB = b.authenticate(credential, request).toCompletableFuture().get();
      identitiesA.credentialGeneration = 4;
      controlB.holdNextCas = true;
      var rotation = a.authenticate(credential, request).toCompletableFuture();
      assertFalse(rotation.isDone());
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> a.resolve(oldA.tokenForResponse(), request).toCompletableFuture().get());
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> b.resolve(oldB.tokenForResponse(), request).toCompletableFuture().get());
      controlB.completeHeldCas();
      var replacement = rotation.get(3, java.util.concurrent.TimeUnit.SECONDS);
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> a.resolve(oldA.tokenForResponse(), request).toCompletableFuture().get());
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> b.resolve(oldB.tokenForResponse(), request).toCompletableFuture().get());
      var resolved = a.resolve(replacement.tokenForResponse(), request).toCompletableFuture().get();
      resolved.release().toCompletableFuture().get();
    }
  }

  @Test
  void authStatusConfigurationMustMatchThePersistedBridge() throws Exception {
    var digest = key(32, 77);
    var source = new FakeConfigurationStore();
    source.record = Optional.of(new AuthConfigurationRecord("milvus", "group", digest, true, 7));
    try (var keys = keyProvider("key-1", temporary.resolve("status-key.bin"));
        var request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
      var service = new AuthSessionService(new FakeStore(),
          new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom()), new FakeIdentityManager(),
          "milvus", "hbase-provider", SCOPE, DATASET, Duration.ofMinutes(5), 1,
          Clock.systemUTC(), new SecureRandom(), null, source, digest);
      assertEquals(7, service.readAuthConfiguration(request).toCompletableFuture().get().revision());
      source.record = Optional.of(new AuthConfigurationRecord("milvus", "group", digest, false, 8));
      var disabled = service.readAuthConfiguration(request).toCompletableFuture().get();
      assertFalse(disabled.enabled());
      assertEquals(8, disabled.revision());
      for (var invalid : java.util.List.of(
          new AuthConfigurationRecord("milvus", "group", key(32, 78), true, 8),
          new AuthConfigurationRecord("milvus", "other", digest, true, 8))) {
        source.record = Optional.of(invalid);
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> service.readAuthConfiguration(request).toCompletableFuture().get());
        assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
            ((AuthSessionException) failure.getCause()).reason());
      }
      source.record = Optional.empty();
      var missing = assertThrows(java.util.concurrent.ExecutionException.class,
          () -> service.readAuthConfiguration(request).toCompletableFuture().get());
      assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
          ((AuthSessionException) missing.getCause()).reason());
    }
  }

  @Test
  void unknownCredentialGenerationRejectsSessionAndReleasesItsResources() throws Exception {
    FakeStore store = new FakeStore();
    FakeIdentityManager identities = new FakeIdentityManager();
    identities.authentication = CompletableFuture.completedFuture(
        AuthorizedBackendIdentity.withUnknownCredentialGeneration(
            "hbase-provider", "milvus-service", "opaque-context", SCOPE, Set.of("group")));
    try (var keys = keyProvider("key-1", temporary.resolve("unknown-key.bin"));
        var request = RequestScope.withTimeout(Duration.ofSeconds(3));
        var credentials = credentials()) {
      var service = service(store, new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom()),
          identities, 1);
      var failure = assertThrows(java.util.concurrent.ExecutionException.class,
          () -> service.authenticate(credentials, request).toCompletableFuture().get());
      assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
          ((AuthSessionException) failure.getCause()).reason());
      assertTrue(store.sessions.isEmpty());
      assertTrue(store.authorities.isEmpty());
      assertEquals(AuthSlot.State.EMPTY, store.slots.get(0).state());
      assertEquals(1, identities.discardedIdentities);
      assertEquals(0, identities.restorableVerifications);
    }
  }

  @Test
  void authenticatesPersistsOnlyDigestAndEnvelopeAndResolvesOnAnotherReplica() throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      FakeIdentityManager firstIdentities = new FakeIdentityManager();
      AuthSessionService firstReplica = service(store, protector, firstIdentities, 2);
      AuthSessionService.IssuedToken issued;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        issued = firstReplica.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      assertEquals(1, store.sessions.size());
      AuthSession persisted = store.sessions.values().iterator().next();
      assertEquals(AuthSession.Status.ACTIVE, persisted.status());
      assertEquals(AuthSlot.State.ACTIVE, store.slots.get(persisted.slotIndex()).state());
      assertFalse(persisted.credentialEnvelope().toString().contains("password"));
      assertEquals(1, firstIdentities.restorableVerifications);

      FakeIdentityManager secondIdentities = new FakeIdentityManager();
      AuthSessionService secondReplica = service(store, protector, secondIdentities, 2);
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
        var resolved = secondReplica.resolve(issued.tokenForResponse(), request)
            .toCompletableFuture().get(3, java.util.concurrent.TimeUnit.SECONDS);
        assertEquals("milvus-service", resolved.identity().subject());
        assertEquals(persisted.subjectDigest(), resolved.session().subjectDigest());
        resolved.release().toCompletableFuture().get(3, java.util.concurrent.TimeUnit.SECONDS);
        resolved.release().toCompletableFuture().get(3, java.util.concurrent.TimeUnit.SECONDS);
      }
      assertEquals(1, secondIdentities.activations);
      assertEquals(1, secondIdentities.releasedIdentityLeases);
      assertEquals(0, secondIdentities.providerCloses,
          "releasing one request identity must not close the shared provider");
      assertTrue(issued.toString().contains("redacted"));
    }
  }

  @Test
  void globallyBoundedSlotsRejectASecondReplicaAndBackendFailureReleasesReservation()
      throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService first = service(store, new FakeIdentityManager(), protector, 1);
      AuthSessionService second = service(store, new FakeIdentityManager(), protector, 1);
      AuthSessionService.IssuedToken issued;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        issued = first.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        var rejected = second.authenticate(credentials, request).toCompletableFuture();
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> rejected.get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.RESOURCE_LIMIT,
            ((AuthSessionException) failure.getCause()).reason());
      }
      assertEquals(1, store.slots.size());
      assertEquals(AuthSlot.State.ACTIVE, store.slots.get(0).state());

      // Expire/retire the existing slot so an invalid login can reserve it and prove cleanup.
      AuthSlot active = store.slots.get(0);
      AuthSlot retiring = new AuthSlot(0, active.generation(), active.sessionId(),
          active.operationId(), AuthSlot.State.RETIRING);
      store.slots.put(0, retiring);
      store.sessions.clear();
      store.slots.put(0, new AuthSlot(0, retiring.generation(), null, null, AuthSlot.State.EMPTY));

      FakeIdentityManager bad = new FakeIdentityManager();
      bad.rejectCredentials = true;
      AuthSessionService invalidLogin = service(store, bad, protector, 1);
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> invalidLogin.authenticate(credentials, request).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertTrue(failure.getCause() instanceof AuthSessionException);
      }
      assertEquals(AuthSlot.State.EMPTY, store.slots.get(0).state());
      assertFalse(store.slots.get(0).sessionId() != null);
      assertTrue(issued.tokenForResponse().length() == 43);
    }
  }

  @Test
  void undeliveredTokenCleanupRetiresOnlyItsSessionAndSlotGeneration() throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService auth = service(store, protector, new FakeIdentityManager(), 1);
      AuthSessionService.IssuedToken first;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        first = auth.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }
      AuthSlot firstSlot = store.slots.get(0);
      assertEquals(AuthSlot.State.ACTIVE, firstSlot.state());
      assertEquals(1, store.sessions.size());

      auth.discardUndelivered(first).toCompletableFuture()
          .get(3, java.util.concurrent.TimeUnit.SECONDS);
      assertTrue(store.sessions.isEmpty());
      assertEquals(AuthSlot.State.EMPTY, store.slots.get(0).state());
      assertEquals(firstSlot.generation(), store.slots.get(0).generation());

      AuthSessionService.IssuedToken second;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        second = auth.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }
      AuthSlot secondSlot = store.slots.get(0);
      assertEquals(AuthSlot.State.ACTIVE, secondSlot.state());
      assertTrue(secondSlot.generation() > firstSlot.generation());
      AuthSession secondSession = store.sessions.values().iterator().next();

      auth.discardUndelivered(first).toCompletableFuture()
          .get(3, java.util.concurrent.TimeUnit.SECONDS);
      assertEquals(AuthSlot.State.ACTIVE, store.slots.get(0).state());
      assertEquals(secondSlot.generation(), store.slots.get(0).generation());
      assertEquals(1, store.sessions.size());
      assertEquals(secondSession, store.sessions.values().iterator().next());

      auth.discardUndelivered(second).toCompletableFuture()
          .get(3, java.util.concurrent.TimeUnit.SECONDS);
      assertTrue(store.sessions.isEmpty());
      assertEquals(AuthSlot.State.EMPTY, store.slots.get(0).state());
      assertEquals(secondSlot.generation(), store.slots.get(0).generation());
    }
  }

  @Test
  void undeliveredCleanupRetainsTheSlotWhenTheSessionIdentityIsUncertain() throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService auth = service(store, protector, new FakeIdentityManager(), 1);
      AuthSessionService.IssuedToken issued;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        issued = auth.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      AuthSession active = store.sessions.values().iterator().next();
      AuthSession mismatched = new AuthSession(key(16, 0), active.tokenDigest(),
          active.subjectDigest(), active.trustDomain(), active.providerId(), active.scope(),
          active.datasetDigest(), active.credentialGeneration(), active.authorizationGeneration(),
          active.createdAtEpochMillis(), active.expiresAtEpochMillis(), active.slotIndex(),
          active.slotGeneration(), active.status(), active.credentialEnvelope());
      store.sessions.put(active.tokenDigest(), mismatched);

      var failure = assertThrows(java.util.concurrent.ExecutionException.class,
          () -> auth.discardUndelivered(issued).toCompletableFuture()
              .get(3, java.util.concurrent.TimeUnit.SECONDS));
      assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
          ((AuthSessionException) failure.getCause()).reason());
      assertEquals(AuthSlot.State.RETIRING, store.slots.get(0).state());
      assertEquals(mismatched, store.sessions.get(active.tokenDigest()));
    }
  }

  @Test
  void failedRestorableVerificationDiscardsIdentityAndReleasesSlot() throws Exception {
    FakeStore store = new FakeStore();
    FakeIdentityManager identities = new FakeIdentityManager();
    identities.restorableFailure = new BackendIdentityException(
        BackendIdentityException.Reason.RESOURCE_LIMIT);
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"));
        RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
        var credentials = credentials()) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService auth = service(store, protector, identities, 1);
      var failure = assertThrows(java.util.concurrent.ExecutionException.class,
          () -> auth.authenticate(credentials, request).toCompletableFuture()
              .get(3, java.util.concurrent.TimeUnit.SECONDS));
      assertEquals(AuthSessionException.Reason.RESOURCE_LIMIT,
          ((AuthSessionException) failure.getCause()).reason());
      assertEquals(1, identities.discardedIdentities);
      assertEquals(AuthSlot.State.EMPTY, store.slots.get(0).state());
      assertTrue(store.sessions.isEmpty());

      identities.restorableFailure = null;
      assertTrue(auth.authenticate(credentials, request).toCompletableFuture()
          .get(3, java.util.concurrent.TimeUnit.SECONDS).tokenForResponse().length() > 0);
      assertEquals(AuthSlot.State.ACTIVE, store.slots.get(0).state());
    }
  }

  @Test
  void synchronousRestorableFailureDiscardsIdentityAndReleasesSlot() throws Exception {
    FakeStore store = new FakeStore();
    FakeIdentityManager identities = new FakeIdentityManager();
    identities.throwRestorable = true;
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"));
        RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
        var credentials = credentials()) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService auth = service(store, protector, identities, 1);
      var failure = assertThrows(java.util.concurrent.ExecutionException.class,
          () -> auth.authenticate(credentials, request).toCompletableFuture()
              .get(3, java.util.concurrent.TimeUnit.SECONDS));
      assertTrue(failure.getCause() instanceof IllegalStateException);
      assertEquals(1, identities.discardedIdentities);
      assertEquals(AuthSlot.State.EMPTY, store.slots.get(0).state());
      assertTrue(store.sessions.isEmpty());
      identities.throwRestorable = false;
      auth.authenticate(credentials, request).toCompletableFuture()
          .get(3, java.util.concurrent.TimeUnit.SECONDS);
      assertEquals(AuthSlot.State.ACTIVE, store.slots.get(0).state());
    }
  }

  @Test
  void cancelledRpcReleasesReservationAfterRealProducerDrains() throws Exception {
    FakeStore store = new FakeStore();
    FakeIdentityManager identities = new FakeIdentityManager();
    identities.authentication = new CompletableFuture<>();
    var producer = new CompletableFuture<Void>();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"));
        RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService auth = service(store, protector, identities, 1);
      request.trackPhysicalProducer(producer);
      var handler = new AuthenticateRpcHandler(auth, () -> request);
      var observerCalled = new AtomicBoolean();
      handler.accept(Rpc.AuthenticateRequest.newBuilder()
          .setName("milvus-service").setPassword("password-1").build(),
          new StreamObserver<>() {
            @Override public void onNext(Rpc.AuthenticateResponse value) { observerCalled.set(true); }
            @Override public void onError(Throwable failure) { observerCalled.set(true); }
            @Override public void onCompleted() { observerCalled.set(true); }
          });
      AuthSlot reserved = store.slots.get(0);
      assertEquals(AuthSlot.State.RESERVED, reserved.state());
      request.cancel();
      identities.authentication.completeExceptionally(new BackendIdentityException(
          BackendIdentityException.Reason.INVALID_CREDENTIALS));
      assertFalse(request.cleanupCompletion().toCompletableFuture().isDone());
      assertEquals(reserved, store.slots.get(0));

      producer.complete(null);
      request.cleanupOutcomeCompletion().toCompletableFuture()
          .get(1, java.util.concurrent.TimeUnit.SECONDS);
      assertFalse(observerCalled.get());
      assertEquals(AuthSlot.State.EMPTY, store.slots.get(0).state());
      assertEquals(reserved.generation(), store.slots.get(0).generation());
      identities.authentication = null;
      try (RequestScope retry = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        auth.authenticate(credentials, retry).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }
      assertEquals(AuthSlot.State.ACTIVE, store.slots.get(0).state());
      assertTrue(store.slots.get(0).generation() > reserved.generation());
    } finally {
      producer.complete(null);
    }
  }

  @Test
  void cancelledAuthenticationKeepsItsSlotUntilPhysicalProducersDrain() throws Exception {
    FakeStore store = new FakeStore();
    FakeIdentityManager identities = new FakeIdentityManager();
    identities.authentication = new CompletableFuture<>();
    var producer = new CompletableFuture<Void>();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"));
        RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
        var credentials = credentials()) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService auth = service(store, protector, identities, 1);
      request.trackPhysicalProducer(producer);
      var result = auth.authenticate(credentials, request).toCompletableFuture();
      assertEquals(AuthSlot.State.RESERVED, store.slots.get(0).state());

      request.cancel();
      identities.authentication.completeExceptionally(new BackendIdentityException(
          BackendIdentityException.Reason.INVALID_CREDENTIALS));
      assertFalse(result.isDone());
      assertEquals(AuthSlot.State.RESERVED, store.slots.get(0).state());

      producer.complete(null);
      assertThrows(java.util.concurrent.ExecutionException.class,
          () -> result.get(3, java.util.concurrent.TimeUnit.SECONDS));
      assertEquals(AuthSlot.State.EMPTY, store.slots.get(0).state());
    } finally {
      producer.complete(null);
    }
  }

  @Test
  void unknownSessionWriteOutcomeKeepsTheGlobalSlotReserved() throws Exception {
    FakeStore store = new FakeStore();
    store.failSessionCreateWithoutWriting = true;
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService auth = service(store, protector, new FakeIdentityManager(), 1);
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> auth.authenticate(credentials, request).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertTrue(failure.getCause() instanceof AuthSessionException);
      }
      assertEquals(AuthSlot.State.RESERVED, store.slots.get(0).state());
      assertTrue(store.sessions.isEmpty());
    }
  }

  @Test
  void revokedAuthorityRejectsAnOtherwiseActiveToken() throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService auth = service(store, protector, new FakeIdentityManager(), 2);
      AuthSessionService.IssuedToken issued;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        issued = auth.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }
      SubjectAuthority authority = store.authorities.values().iterator().next();
      store.authorities.put(authority.subjectDigest(), new SubjectAuthority(authority.subjectDigest(),
          authority.trustDomain(), authority.providerId(), authority.scope(),
          authority.credentialGeneration(), authority.authorizationGeneration() + 1,
          SubjectAuthority.State.REVOKED));
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> auth.resolve(issued.tokenForResponse(), request).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.INVALID_TOKEN,
            ((AuthSessionException) failure.getCause()).reason());
      }
    }
  }

  @Test
  void credentialRotationInstallsDurableGroupBarrierBeforeNewSessionIsIssued() throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      FakeIdentityManager identities = new FakeIdentityManager();
      FakeControlStore commitControl = new FakeControlStore();
      AuthSessionService auth = service(store, protector, identities, 2,
          new AuthorizationBarrierInstaller(commitControl, Clock.fixed(
              Instant.ofEpochMilli(10), ZoneOffset.UTC)));
      AuthSessionService.IssuedToken previous;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        previous = auth.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      identities.credentialGeneration = 4;
      AuthSessionService.IssuedToken rotated;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        rotated = auth.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      SubjectAuthority authority = store.authorities.values().iterator().next();
      assertEquals(SubjectAuthority.State.ACTIVE, authority.state());
      assertEquals(4, authority.credentialGeneration());
      assertEquals(2, authority.authorizationGeneration());
      assertTrue(authority.revocationTargets().isEmpty());
      assertEquals(1, commitControl.current().authorizationBarrierGeneration());
      assertEquals(4, store.sessions.values().stream()
          .filter(session -> session.status() == AuthSession.Status.ACTIVE)
          .filter(session -> session.credentialGeneration() == 4)
          .findFirst().orElseThrow().credentialGeneration());

      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> auth.resolve(previous.tokenForResponse(), request).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.INVALID_TOKEN,
            ((AuthSessionException) failure.getCause()).reason());
      }
      assertEquals(43, rotated.tokenForResponse().length());
    }
  }

  @Test
  void compatibilityConstructorLeavesRotationRevokingAndAConfiguredReplicaResumesIt()
      throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      FakeIdentityManager identities = new FakeIdentityManager();
      AuthSessionService compatibility = service(store, protector, identities, 2);
      AuthSessionService.IssuedToken previous;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        previous = compatibility.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      identities.credentialGeneration = 4;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> compatibility.authenticate(credentials, request).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
            ((AuthSessionException) failure.getCause()).reason());
      }
      SubjectAuthority pending = store.authorities.values().iterator().next();
      assertEquals(SubjectAuthority.State.REVOKING, pending.state());
      assertEquals(0, pending.revocationTargets().getFirst().barrierGeneration());

      var commitControl = new FakeControlStore();
      AuthSessionService recovering = service(store, protector, identities, 2,
          new AuthorizationBarrierInstaller(commitControl, Clock.fixed(
              Instant.ofEpochMilli(10), ZoneOffset.UTC)));
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        recovering.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      SubjectAuthority recovered = store.authorities.values().iterator().next();
      assertEquals(SubjectAuthority.State.ACTIVE, recovered.state());
      assertEquals(4, recovered.credentialGeneration());
      assertEquals(1, commitControl.current().authorizationBarrierGeneration());
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> recovering.resolve(previous.tokenForResponse(), request).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.INVALID_TOKEN,
            ((AuthSessionException) failure.getCause()).reason());
      }
    }
  }

  @Test
  void rotationResumesAfterAnUnknownAuthorityWriteAtEveryPersistedPhase() throws Exception {
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      for (int failedWrite = 1; failedWrite <= 4; failedWrite++) {
        FakeStore store = new FakeStore();
        FakeIdentityManager identities = new FakeIdentityManager();
        FakeControlStore control = new FakeControlStore();
        var installer = new AuthorizationBarrierInstaller(control, Clock.fixed(
            Instant.ofEpochMilli(10), ZoneOffset.UTC));
        AuthSessionService first = service(store, protector, identities, 3, installer);
        AuthSessionService.IssuedToken oldToken;
        try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
            var credentials = credentials()) {
          oldToken = first.authenticate(credentials, request).toCompletableFuture()
              .get(3, java.util.concurrent.TimeUnit.SECONDS);
        }

        identities.credentialGeneration = 4;
        store.failAuthorityCasAfterWrite = failedWrite;
        try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
            var credentials = credentials()) {
          assertThrows(java.util.concurrent.ExecutionException.class,
              () -> first.authenticate(credentials, request).toCompletableFuture()
                  .get(3, java.util.concurrent.TimeUnit.SECONDS));
        }
        SubjectAuthority persisted = store.authorities.values().iterator().next();
        assertEquals(4, persisted.credentialGeneration());
        assertEquals(2, persisted.authorizationGeneration());
        assertEquals(failedWrite == 4 ? SubjectAuthority.State.ACTIVE : SubjectAuthority.State.REVOKING,
            persisted.state());
        assertEquals(failedWrite >= 3 ? 1 : 0, control.current().authorizationBarrierGeneration());
        assertEquals(1, store.sessions.size());
        try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
          var failure = assertThrows(java.util.concurrent.ExecutionException.class,
              () -> first.resolve(oldToken.tokenForResponse(), request).toCompletableFuture()
                  .get(3, java.util.concurrent.TimeUnit.SECONDS));
          assertEquals(AuthSessionException.Reason.INVALID_TOKEN,
              ((AuthSessionException) failure.getCause()).reason());
        }

        AuthSessionService recovering = service(store, protector, identities, 3, installer);
        AuthSessionService.IssuedToken newToken;
        try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
            var credentials = credentials()) {
          newToken = recovering.authenticate(credentials, request).toCompletableFuture()
              .get(3, java.util.concurrent.TimeUnit.SECONDS);
        }
        SubjectAuthority recovered = store.authorities.values().iterator().next();
        assertEquals(SubjectAuthority.State.ACTIVE, recovered.state());
        assertEquals(4, recovered.credentialGeneration());
        assertEquals(2, recovered.authorizationGeneration());
        assertEquals(1, control.current().authorizationBarrierGeneration());
        assertEquals(2, store.sessions.size());
        try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
          var failure = assertThrows(java.util.concurrent.ExecutionException.class,
              () -> recovering.resolve(oldToken.tokenForResponse(), request).toCompletableFuture()
                  .get(3, java.util.concurrent.TimeUnit.SECONDS));
          assertEquals(AuthSessionException.Reason.INVALID_TOKEN,
              ((AuthSessionException) failure.getCause()).reason());
          var resolved = recovering.resolve(newToken.tokenForResponse(), request).toCompletableFuture()
              .get(3, java.util.concurrent.TimeUnit.SECONDS);
          resolved.release().toCompletableFuture().get(3, java.util.concurrent.TimeUnit.SECONDS);
        }
      }
    }
  }

  @Test
  void newerRotationFencesAnOlderRotationWaitingForBarrierCas() throws Exception {
    FakeStore store = new FakeStore();
    FakeControlStore control = new FakeControlStore();
    FakeIdentityManager olderIdentities = new FakeIdentityManager();
    FakeIdentityManager newerIdentities = new FakeIdentityManager();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      var installer = new AuthorizationBarrierInstaller(control, Clock.fixed(
          Instant.ofEpochMilli(10), ZoneOffset.UTC));
      AuthSessionService older = service(store, protector, olderIdentities, 3, installer);
      AuthSessionService newer = service(store, protector, newerIdentities, 3, installer);
      AuthSessionService.IssuedToken original;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        original = older.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      olderIdentities.credentialGeneration = 4;
      newerIdentities.credentialGeneration = 5;
      control.holdNextCas = true;
      try (RequestScope oldRequest = RequestScope.withTimeout(Duration.ofSeconds(3));
          var oldCredentials = credentials();
          RequestScope newRequest = RequestScope.withTimeout(Duration.ofSeconds(3));
          var newCredentials = credentials()) {
        var delayed = older.authenticate(oldCredentials, oldRequest).toCompletableFuture();
        assertFalse(delayed.isDone());
        assertEquals(SubjectAuthority.State.REVOKING,
            store.authorities.values().iterator().next().state());

        var current = newer.authenticate(newCredentials, newRequest).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
        control.completeHeldCas();
        var olderFailure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> delayed.get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.PERMISSION_DENIED,
            ((AuthSessionException) olderFailure.getCause()).reason());
        var authority = store.authorities.values().iterator().next();
        assertEquals(SubjectAuthority.State.ACTIVE, authority.state());
        assertEquals(5, authority.credentialGeneration());
        assertEquals(3, authority.authorizationGeneration());
        assertEquals(1, control.current().authorizationBarrierGeneration());
        assertEquals(2, store.sessions.size());
        var originalFailure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> newer.resolve(original.tokenForResponse(), newRequest).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.INVALID_TOKEN,
            ((AuthSessionException) originalFailure.getCause()).reason());
        var resolved = newer.resolve(current.tokenForResponse(), newRequest).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
        resolved.release().toCompletableFuture().get(3, java.util.concurrent.TimeUnit.SECONDS);
        var staleReplicaFailure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> older.authenticate(oldCredentials, oldRequest).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.PERMISSION_DENIED,
            ((AuthSessionException) staleReplicaFailure.getCause()).reason());
        assertEquals(2, store.sessions.size());
      }
    }
  }

  @Test
  void activationIsDiscardedWhenAuthorityChangesBeforeIdentityIsPublished() throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      AuthSessionService firstReplica = service(store, protector, new FakeIdentityManager(), 2);
      AuthSessionService.IssuedToken issued;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        issued = firstReplica.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      AuthSession session = store.sessions.values().iterator().next();
      SubjectAuthority authority = store.authorities.get(session.subjectDigest());
      FakeIdentityManager activating = new FakeIdentityManager();
      activating.activation = new CompletableFuture<>();
      AuthSessionService secondReplica = service(store, protector, activating, 2);
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
        var resolution = secondReplica.resolve(issued.tokenForResponse(), request).toCompletableFuture();
        assertEquals(1, activating.activations);

        store.authorities.put(authority.subjectDigest(), new SubjectAuthority(
            authority.subjectDigest(), authority.trustDomain(), authority.providerId(), authority.scope(),
            authority.credentialGeneration(), authority.authorizationGeneration() + 1,
            SubjectAuthority.State.REVOKED));
        activating.activation.complete(
            new SessionIdentityLease(FakeIdentityManager.identity("milvus-service", session.scope()),
                () -> {
                  activating.releasedIdentityLeases++;
                  return CompletableFuture.completedFuture(null);
                }));

        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> resolution.get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.INVALID_TOKEN,
            ((AuthSessionException) failure.getCause()).reason());
        assertEquals(1, activating.releasedIdentityLeases);
      }
    }
  }

  @Test
  void activationFailureDoesNotReleaseOrCloseAnotherProviderOwnedContext() throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      FakeIdentityManager identities = new FakeIdentityManager();
      AuthorizedBackendIdentity otherIdentity = FakeIdentityManager.identity("other", SCOPE);
      identities.liveIdentity = otherIdentity;
      identities.activation = CompletableFuture.failedFuture(new BackendIdentityException(
          BackendIdentityException.Reason.BACKEND_UNAVAILABLE));
      AuthSessionService auth = service(store, protector, identities, 1);
      AuthSessionService.IssuedToken issued;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        issued = auth.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3))) {
        var failure = assertThrows(java.util.concurrent.ExecutionException.class,
            () -> auth.resolve(issued.tokenForResponse(), request).toCompletableFuture()
                .get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
            ((AuthSessionException) failure.getCause()).reason());
      }
      assertEquals(0, identities.releasedIdentityLeases);
      assertEquals(0, identities.providerCloses);
      assertEquals(otherIdentity, identities.liveIdentity,
          "a failed activation must not retire a different identity");
    }
  }

  @Test
  void cancelledRequestReleasesIdentityThatActivatesLate() throws Exception {
    FakeStore store = new FakeStore();
    try (var keys = keyProvider("key-1", temporary.resolve("key.bin"))) {
      var protector = new AesGcmCredentialEnvelopeProtector(keys, new SecureRandom());
      FakeIdentityManager firstIdentities = new FakeIdentityManager();
      AuthSessionService first = service(store, protector, firstIdentities, 1);
      AuthSessionService.IssuedToken issued;
      try (RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
          var credentials = credentials()) {
        issued = first.authenticate(credentials, request).toCompletableFuture()
            .get(3, java.util.concurrent.TimeUnit.SECONDS);
      }

      FakeIdentityManager activating = new FakeIdentityManager();
      activating.activation = new CompletableFuture<>();
      AuthSessionService second = service(store, protector, activating, 1);
      RequestScope request = RequestScope.withTimeout(Duration.ofSeconds(3));
      var resolution = second.resolve(issued.tokenForResponse(), request).toCompletableFuture();
      request.cancel();
      AuthSession persisted = store.sessions.values().iterator().next();
      activating.activation.complete(new SessionIdentityLease(
          FakeIdentityManager.identity("milvus-service", persisted.scope()), () -> {
            activating.releasedIdentityLeases++;
            return CompletableFuture.completedFuture(null);
          }));

      var failure = assertThrows(java.util.concurrent.ExecutionException.class,
          () -> resolution.get(3, java.util.concurrent.TimeUnit.SECONDS));
      assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
          ((AuthSessionException) failure.getCause()).reason());
      assertEquals(1, activating.releasedIdentityLeases);
      assertEquals(0, activating.providerCloses);
    }
  }

  private AuthSessionService service(FakeStore store, AesGcmCredentialEnvelopeProtector protector,
      FakeIdentityManager identities, int slots) {
    return service(store, identities, protector, slots);
  }

  private AuthSessionService service(FakeStore store, FakeIdentityManager identities,
      AesGcmCredentialEnvelopeProtector protector, int slots) {
    return service(store, protector, identities, slots, null);
  }

  private AuthSessionService service(FakeStore store, AesGcmCredentialEnvelopeProtector protector,
      FakeIdentityManager identities, int slots, AuthorizationBarrierInstaller barrierInstaller) {
    return new AuthSessionService(store, protector, identities, "milvus", "hbase-provider", SCOPE,
        DATASET, Duration.ofMinutes(5), slots, Clock.systemUTC(), new SecureRandom(),
        barrierInstaller);
  }

  private FileCredentialKeyProvider keyProvider(String id, Path path) throws Exception {
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 0x5a);
    Files.write(path, key);
    Files.setPosixFilePermissions(path, Set.of(
        java.nio.file.attribute.PosixFilePermission.OWNER_READ,
        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
    Arrays.fill(key, (byte) 0);
    return new FileCredentialKeyProvider(id, Map.of(id, path));
  }

  private static BackendCredentials credentials() {
    return new BackendCredentials("milvus-service", "password-1".toCharArray());
  }

  private static ByteKey key(int length, int value) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, (byte) value);
    return ByteKey.copyOf(bytes);
  }

  private static final class FakeIdentityManager implements SessionIdentityManager {
    private int restorableVerifications;
    private int activations;
    private int discardedIdentities;
    private boolean rejectCredentials;
    private Throwable restorableFailure;
    private boolean throwRestorable;
    private CompletableFuture<AuthorizedBackendIdentity> authentication;
    private CompletableFuture<SessionIdentityLease> activation;
    private int releasedIdentityLeases;
    private int providerCloses;
    private long credentialGeneration = 3;
    private AuthorizedBackendIdentity liveIdentity;

    @Override
    public CompletionStage<AuthorizedBackendIdentity> authenticate(
        BackendCredentials credentials, AuthenticationScope scope) {
      if (authentication != null) return authentication;
      if (rejectCredentials) return CompletableFuture.failedFuture(new BackendIdentityException(
          BackendIdentityException.Reason.INVALID_CREDENTIALS));
      return CompletableFuture.completedFuture(
          identity(credentials.principal(), scope, credentialGeneration));
    }

    @Override
    public CompletionStage<Void> verifyRestorable(
        BackendCredentials credentials, AuthorizedBackendIdentity authenticatedIdentity) {
      restorableVerifications++;
      if (throwRestorable) throw new IllegalStateException("restorable verification failed");
      if (restorableFailure != null) return CompletableFuture.failedFuture(restorableFailure);
      return CompletableFuture.completedFuture(null);
    }

    @Override
    public CompletionStage<SessionIdentityLease> activate(
        AuthSession session, BackendCredentials credentials) {
      activations++;
      if (activation != null) return activation;
      AuthorizedBackendIdentity activated = identity(
          credentials.principal(), session.scope(), session.credentialGeneration());
      liveIdentity = activated;
      return CompletableFuture.completedFuture(new SessionIdentityLease(activated, () -> {
        releasedIdentityLeases++;
        if (liveIdentity == activated) liveIdentity = null;
        return CompletableFuture.completedFuture(null);
      }));
    }

    @Override
    public CompletionStage<Void> discardUnpublished(AuthorizedBackendIdentity identity) {
      discardedIdentities++;
      return CompletableFuture.completedFuture(null);
    }

    @Override public void close() { providerCloses++; }

    private static AuthorizedBackendIdentity identity(String subject, AuthenticationScope scope) {
      return identity(subject, scope, 3);
    }

    private static AuthorizedBackendIdentity identity(
        String subject, AuthenticationScope scope, long credentialGeneration) {
      return new AuthorizedBackendIdentity("hbase-provider", subject, "opaque-context",
          scope, Set.of(scope.tableGroupId()), credentialGeneration);
    }
  }

  private static final class FakeConfigurationStore implements AuthConfigurationStore {
    private Optional<AuthConfigurationRecord> record = Optional.empty();

    @Override public CompletionStage<Optional<AuthConfigurationRecord>> readConfiguration(
        String tableGroupId, RequestScope scope) {
      return CompletableFuture.completedFuture(record);
    }

    @Override public CompletionStage<Boolean> createConfigurationIfAbsent(
        AuthConfigurationRecord initial, RequestScope scope) {
      throw new UnsupportedOperationException();
    }

    @Override public CompletionStage<Boolean> compareAndSetConfiguration(
        AuthConfigurationRecord observed, AuthConfigurationRecord replacement, RequestScope scope) {
      throw new UnsupportedOperationException();
    }
  }

  private static final class FakeDeploymentRegistry implements AuthDeploymentRegistryStore {
    private AuthDeploymentRegistry current;
    private FakeDeploymentRegistry(AuthDeploymentRegistry current) { this.current = current; }
    @Override public synchronized CompletionStage<Optional<AuthDeploymentRegistry>> readRegistry(RequestScope scope) {
      return CompletableFuture.completedFuture(Optional.of(current));
    }
    @Override public CompletionStage<Boolean> createRegistryIfAbsent(AuthDeploymentRegistry initial, RequestScope scope) {
      throw new AssertionError("normal login must not create the deployment registry");
    }
    @Override public synchronized CompletionStage<Boolean> compareAndSetRegistry(AuthDeploymentRegistry observed,
        AuthDeploymentRegistry replacement, RequestScope scope) {
      if (!current.equals(observed) || !observed.permitsReplacement(replacement)) {
        return CompletableFuture.completedFuture(false);
      }
      current = replacement;
      return CompletableFuture.completedFuture(true);
    }
  }

  private static final class FakeStore implements AuthSessionStore {
    private final Map<ByteKey, AuthSession> sessions = new HashMap<>();
    private final Map<Integer, AuthSlot> slots = new HashMap<>();
    private final Map<ByteKey, SubjectAuthority> authorities = new HashMap<>();
    private boolean failSessionCreateWithoutWriting;
    private int failAuthorityCasAfterWrite;

    @Override public synchronized CompletionStage<Optional<AuthSession>> readSession(
        ByteKey digest, RequestScope scope) {
      return CompletableFuture.completedFuture(Optional.ofNullable(sessions.get(digest)));
    }
    @Override public synchronized CompletionStage<Boolean> createSessionIfAbsent(
        AuthSession session, RequestScope scope) {
      if (failSessionCreateWithoutWriting) {
        failSessionCreateWithoutWriting = false;
        return CompletableFuture.failedFuture(new IllegalStateException("simulated unknown write"));
      }
      if (sessions.containsKey(session.tokenDigest())) return CompletableFuture.completedFuture(false);
      sessions.put(session.tokenDigest(), session);
      return CompletableFuture.completedFuture(true);
    }
    @Override public synchronized CompletionStage<Boolean> deleteSessionIfUnchanged(
        AuthSession observed, RequestScope scope) {
      return CompletableFuture.completedFuture(sessions.remove(observed.tokenDigest(), observed));
    }
    @Override public synchronized CompletionStage<Boolean> compareAndSetSession(
        AuthSession observed, AuthSession replacement, RequestScope scope) {
      if (!sessions.getOrDefault(observed.tokenDigest(), observed).equals(observed)
          || !sessions.containsKey(observed.tokenDigest())) return CompletableFuture.completedFuture(false);
      sessions.put(observed.tokenDigest(), replacement);
      return CompletableFuture.completedFuture(true);
    }
    @Override public synchronized CompletionStage<Optional<AuthSlot>> readSlot(
        int index, RequestScope scope) {
      return CompletableFuture.completedFuture(Optional.ofNullable(slots.get(index)));
    }
    @Override public synchronized CompletionStage<Boolean> createSlotIfAbsent(
        AuthSlot slot, RequestScope scope) {
      if (slots.containsKey(slot.index())) return CompletableFuture.completedFuture(false);
      slots.put(slot.index(), slot);
      return CompletableFuture.completedFuture(true);
    }
    @Override public synchronized CompletionStage<Boolean> compareAndSetSlot(
        AuthSlot observed, AuthSlot replacement, RequestScope scope) {
      if (!observed.equals(slots.get(observed.index()))) return CompletableFuture.completedFuture(false);
      slots.put(observed.index(), replacement);
      return CompletableFuture.completedFuture(true);
    }
    @Override public synchronized CompletionStage<Optional<SubjectAuthority>> readAuthority(
        ByteKey subject, RequestScope scope) {
      return CompletableFuture.completedFuture(Optional.ofNullable(authorities.get(subject)));
    }
    @Override public synchronized CompletionStage<Boolean> createAuthorityIfAbsent(
        SubjectAuthority authority, RequestScope scope) {
      if (authority.state() != SubjectAuthority.State.ACTIVE
          || !authority.revocationTargets().isEmpty()
          || authorities.containsKey(authority.subjectDigest())) {
        return CompletableFuture.completedFuture(false);
      }
      authorities.put(authority.subjectDigest(), authority);
      return CompletableFuture.completedFuture(true);
    }
    @Override public synchronized CompletionStage<Boolean> compareAndSetAuthority(
        SubjectAuthority observed, SubjectAuthority replacement, RequestScope scope) {
      if (!observed.equals(authorities.get(observed.subjectDigest()))
          || !observed.allowsTransitionTo(replacement)) {
        return CompletableFuture.completedFuture(false);
      }
      authorities.put(observed.subjectDigest(), replacement);
      if (failAuthorityCasAfterWrite > 0 && --failAuthorityCasAfterWrite == 0) {
        return CompletableFuture.failedFuture(new BackendFailure(BackendFailure.Category.UNKNOWN));
      }
      return CompletableFuture.completedFuture(true);
    }
  }

  private static final class FakeControlStore implements CommitControlStore {
    private final AtomicReference<ControlSnapshot> current = new AtomicReference<>(
        snapshot(initialBarrierState()));
    private boolean holdNextCas;
    private ControlSnapshot heldObserved;
    private CommitState heldReplacement;
    private CompletableFuture<Boolean> heldResult;

    private CommitState current() { return current.get().state(); }

    @Override public CompletableFuture<Optional<ControlSnapshot>> read(RequestScope scope) {
      return CompletableFuture.completedFuture(Optional.of(current.get()));
    }

    @Override public CompletableFuture<Boolean> initializeIfAbsent(
        CommitState initialState, RequestScope scope) {
      throw new UnsupportedOperationException();
    }

    @Override public CompletableFuture<Boolean> compareAndSet(
        ControlSnapshot observed, CommitState replacement, RequestScope scope) {
      synchronized (current) {
        if (holdNextCas) {
          holdNextCas = false;
          heldObserved = observed;
          heldReplacement = replacement;
          heldResult = new CompletableFuture<>();
          return heldResult;
        }
        if (current.get() != observed) return CompletableFuture.completedFuture(false);
        current.set(snapshot(replacement));
        return CompletableFuture.completedFuture(true);
      }
    }

    private void completeHeldCas() {
      boolean applied;
      synchronized (current) {
        applied = current.get() == heldObserved;
        if (applied) current.set(snapshot(heldReplacement));
      }
      heldResult.complete(applied);
    }

    private static ControlSnapshot snapshot(CommitState state) {
      return new ControlSnapshot(state, java.nio.ByteBuffer.allocate(Long.BYTES)
          .putLong(state.stateVersion()).array());
    }

    private static CommitState initialBarrierState() {
      String owner = "auth-session-test-owner";
      return CommitState.initial(key(32, 7), 1).claimOwner(owner, 1, 100_000)
          .enableAuthorizationBarrier(owner, 1, 2);
    }
  }
}
